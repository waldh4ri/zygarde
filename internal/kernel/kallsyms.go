// Package kernel reads facts about the running kernel from procfs and sysfs.
package kernel

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Kallsyms holds core-kernel symbol addresses from /proc/kallsyms.
// Module symbols are not included.
type Kallsyms struct {
	addrs  map[string]uint64
	names  map[uint64]string // built on first Name() call
	sorted []symbol          // built on first Lookup() call
}

// Name returns the symbol at exactly addr (the first one, if aliased).
func (k *Kallsyms) Name(addr uint64) (string, bool) {
	if k.names == nil {
		k.names = make(map[uint64]string, len(k.addrs))
		for name, a := range k.addrs {
			if prev, ok := k.names[a]; !ok || name < prev {
				k.names[a] = name
			}
		}
	}
	n, ok := k.names[addr]
	return n, ok
}

// ErrAddressesHidden means /proc/kallsyms reports zero addresses,
// usually because of kernel.kptr_restrict or missing privileges.
var ErrAddressesHidden = errors.New("/proc/kallsyms addresses are hidden (kptr_restrict or insufficient privileges)")

// LoadKallsyms parses /proc/kallsyms.
func LoadKallsyms() (*Kallsyms, error) {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseKallsyms(f)
}

// ParseKallsyms parses kallsyms-formatted text: "address type name [module]".
func ParseKallsyms(r io.Reader) (*Kallsyms, error) {
	ks := &Kallsyms{addrs: make(map[string]uint64, 1<<17)}
	nonZero := false

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 || len(fields) > 3 {
			// Skip malformed lines and module symbols ("[module]" 4th field).
			continue
		}
		addr, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil {
			continue
		}
		if addr != 0 {
			nonZero = true
		}
		if _, dup := ks.addrs[fields[2]]; !dup {
			ks.addrs[fields[2]] = addr
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading kallsyms: %w", err)
	}
	if len(ks.addrs) > 0 && !nonZero {
		return nil, ErrAddressesHidden
	}
	return ks, nil
}

// Addr returns the address of a core-kernel symbol.
func (k *Kallsyms) Addr(name string) (uint64, bool) {
	a, ok := k.addrs[name]
	return a, ok
}

// FirstWithPrefix returns the alphabetically first symbol with the prefix,
// e.g. to find LTO-renamed static functions ("filldir64.llvm.123").
func (k *Kallsyms) FirstWithPrefix(prefix string) (string, bool) {
	best := ""
	for name := range k.addrs {
		if strings.HasPrefix(name, prefix) && (best == "" || name < best) {
			best = name
		}
	}
	return best, best != ""
}

// Has reports whether a core-kernel symbol exists.
func (k *Kallsyms) Has(name string) bool {
	_, ok := k.addrs[name]
	return ok
}

// Lookup returns the symbol containing addr: the nearest one at or below it,
// and addr's offset from it. Addresses below the first symbol are not found.
func (k *Kallsyms) Lookup(addr uint64) (string, uint64, bool) {
	if k.sorted == nil {
		k.sorted = make([]symbol, 0, len(k.addrs))
		for name, a := range k.addrs {
			k.sorted = append(k.sorted, symbol{a, name})
		}
		sort.Slice(k.sorted, func(i, j int) bool {
			if k.sorted[i].addr != k.sorted[j].addr {
				return k.sorted[i].addr < k.sorted[j].addr
			}
			return k.sorted[i].name < k.sorted[j].name
		})
	}
	i := sort.Search(len(k.sorted), func(i int) bool { return k.sorted[i].addr > addr })
	if i == 0 {
		return "", 0, false
	}
	s := k.sorted[i-1]
	// Prefer the first name at that address (aliases sort by name).
	for i-2 >= 0 && k.sorted[i-2].addr == s.addr {
		i--
		s = k.sorted[i-1]
	}
	return s.name, addr - s.addr, true
}

type symbol struct {
	addr uint64
	name string
}

// Image is the core kernel image's address ranges, from kallsyms:
// functions live in [TextStart, TextEnd), data (sys_call_table...) in
// [TextStart, End).
type Image struct {
	TextStart, TextEnd, End uint64
	// HasData is false when kallsyms lists no end of image (no
	// CONFIG_KALLSYMS_ALL): End is then TextEnd and data can't be checked.
	HasData bool
}

// vsyscallPage is the x86-64 legacy vsyscall page. Reading it with
// copy_from_kernel_nofault() oopses kernels without commit 32019c659ecf
// ("x86/mm: Disallow vsyscall page read for copy_from_kernel_nofault()").
const vsyscallPage = 0xffffffffff600000

// maxImageSize bounds a plausible kernel image (text, data and bss).
const maxImageSize = 1 << 30

// ErrImageRange means kallsyms reports an implausible kernel image range.
var ErrImageRange = errors.New("kallsyms reports an implausible kernel image range")

// Image returns the kernel image's ranges after checking they are
// plausible: in the kernel half of the address space, ordered, smaller than
// 1 GiB and clear of the vsyscall page. kallsyms can be filtered by a
// rootkit, and these ranges decide which addresses BPF may read.
func (k *Kallsyms) Image() (Image, error) {
	var img Image
	var ok bool
	if img.TextStart, ok = k.Addr("_stext"); !ok {
		return img, errors.New("_stext is not in /proc/kallsyms")
	}
	if img.TextEnd, ok = k.Addr("_etext"); !ok {
		return img, errors.New("_etext is not in /proc/kallsyms")
	}
	for _, sym := range []string{"_end", "__bss_stop", "__end_rodata"} {
		if img.End, ok = k.Addr(sym); ok {
			break
		}
	}
	if ok {
		img.HasData = true
	} else {
		img.End = img.TextEnd // kernels without CONFIG_KALLSYMS_ALL list no data symbols
	}
	if err := img.check(); err != nil {
		return img, err
	}
	return img, nil
}

func (img Image) check() error {
	const kernelHalf = 0xff00000000000000
	switch {
	case img.TextStart < kernelHalf:
		return fmt.Errorf("%w: _stext %#x is not a kernel address", ErrImageRange, img.TextStart)
	case img.TextEnd <= img.TextStart || img.End < img.TextEnd:
		return fmt.Errorf("%w: _stext %#x, _etext %#x, end %#x are out of order", ErrImageRange, img.TextStart, img.TextEnd, img.End)
	case img.End-img.TextStart > maxImageSize:
		return fmt.Errorf("%w: %#x-%#x spans more than 1 GiB", ErrImageRange, img.TextStart, img.End)
	case img.TextStart <= vsyscallPage+4096 && vsyscallPage < img.End:
		return fmt.Errorf("%w: %#x-%#x includes the vsyscall page", ErrImageRange, img.TextStart, img.End)
	}
	return nil
}

// InText reports whether [addr, addr+size) lies within the kernel's text.
func (img Image) InText(addr, size uint64) bool {
	return addr >= img.TextStart && addr+size >= addr && addr+size <= img.TextEnd
}

// InImage reports whether [addr, addr+size) lies within the kernel image.
func (img Image) InImage(addr, size uint64) bool {
	return addr >= img.TextStart && addr+size >= addr && addr+size <= img.End
}
