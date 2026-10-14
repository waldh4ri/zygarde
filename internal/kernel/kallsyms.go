// Package kernel reads facts about the running kernel from procfs and sysfs.
package kernel

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Kallsyms holds core-kernel symbol addresses from /proc/kallsyms.
// Module symbols are not included.
type Kallsyms struct {
	addrs map[string]uint64
	names map[uint64]string // built on first Name() call
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
