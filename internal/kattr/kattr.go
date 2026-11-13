// Package kattr attributes kernel addresses to the code or data that owns
// them: the core kernel, a visible module, a BPF program or trampoline, an
// ftrace trampoline or a kprobe instruction page.
//
// An execution pointer (a hook, an operations table entry) that resolves to
// none of these runs code that no visible object accounts for: typically a
// module that removed itself from the module list after installing a hook.
// That UNKNOWN result is the signal the pointer-checking Cells look for.
//
// Sources, all readable by root even when /proc/kallsyms is the only symbol
// table: /proc/kallsyms (with its [module], [bpf], [__builtin__ftrace] and
// [__builtin__kprobes] tags), /proc/modules, /sys/module/*/sections and
// /proc/vmallocinfo, which lists every module, BPF and trampoline allocation
// with the function that made it.
package kattr

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Kind is what owns an address.
type Kind int

const (
	Unknown    Kind = iota // no visible owner
	Kernel                 // core kernel text
	KernelData             // core kernel image, outside its text
	Module                 // a module listed in /proc/modules
	BPF                    // a BPF program, trampoline or dispatcher
	Ftrace                 // an ftrace trampoline
	Kprobe                 // a kprobe instruction slot page
)

func (k Kind) String() string {
	switch k {
	case Kernel:
		return "kernel"
	case KernelData:
		return "kernel data"
	case Module:
		return "module"
	case BPF:
		return "BPF"
	case Ftrace:
		return "ftrace trampoline"
	case Kprobe:
		return "kprobe instruction page"
	}
	return "unknown"
}

// Attribution says who owns an address.
type Attribution struct {
	Kind   Kind
	Module string // for Module
	Symbol string // nearest symbol at or below the address, if any
	Offset uint64 // from Symbol
}

// Owner describes the owner: "kernel", "module ext4", "BPF"...
func (a Attribution) Owner() string {
	if a.Kind == Module {
		return "module " + a.Module
	}
	return a.Kind.String()
}

// Where formats the attribution as "tcp4_seq_show+0x0 (kernel)".
func (a Attribution) Where() string {
	if a.Symbol == "" {
		return a.Owner()
	}
	return fmt.Sprintf("%s+%#x (%s)", a.Symbol, a.Offset, a.Owner())
}

// BaseName strips compiler suffixes from a symbol name ("foo.llvm.123",
// "foo.cfi_jt", "foo.isra.0" -> "foo").
func BaseName(sym string) string {
	if i := strings.IndexByte(sym, '.'); i > 0 {
		return sym[:i]
	}
	return sym
}

// ModuleInfo is one line of /proc/modules.
type ModuleInfo struct {
	Name   string
	Base   uint64
	Size   uint64
	UsedBy []string
}

// Area is one /proc/vmallocinfo allocation.
type Area struct {
	Start, End uint64
	Caller     string // allocating function, without offset
}

type symbol struct {
	addr  uint64
	name  string
	kind  Kind   // Kernel for core symbols
	owner string // module name
}

// Resolver attributes addresses. Build it with Load or New.
type Resolver struct {
	core    []symbol // core kernel symbols, sorted
	anchors []symbol // module/BPF/trampoline symbols, module bases and sections, sorted
	byName  map[string][]uint64

	textStart, textEnd uint64
	initStart, initEnd uint64
	imageEnd           uint64

	modules map[string]*ModuleInfo
	areas   []Area // sorted, non-overlapping
}

// ErrAddressesHidden means /proc/kallsyms reports zero addresses
// (kernel.kptr_restrict or missing privileges).
var ErrAddressesHidden = errors.New("/proc/kallsyms addresses are hidden (kptr_restrict or insufficient privileges)")

// Load reads the running kernel's symbol, module and allocation lists.
// Only /proc/kallsyms is required; the others refine attribution.
func Load() (*Resolver, error) {
	ks, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	defer ks.Close()

	var mods io.Reader
	if f, err := os.Open("/proc/modules"); err == nil {
		defer f.Close()
		mods = f
	}
	var vm io.Reader
	if f, err := os.Open("/proc/vmallocinfo"); err == nil {
		defer f.Close()
		vm = f
	}
	return New(ks, mods, ReadSections("/sys/module"), vm)
}

// ReadSections returns, per module, the start address of each ELF section
// from <dir>/<module>/sections. Unreadable entries are skipped.
func ReadSections(dir string) map[string]map[string]uint64 {
	out := map[string]map[string]uint64{}
	mods, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, m := range mods {
		sdir := filepath.Join(dir, m.Name(), "sections")
		entries, err := os.ReadDir(sdir)
		if err != nil {
			continue
		}
		secs := map[string]uint64{}
		for _, e := range entries {
			// sysfs attributes: small, regular, not attacker-controlled.
			b, err := os.ReadFile(filepath.Join(sdir, e.Name()))
			if err != nil || len(b) > 64 {
				continue
			}
			if a, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(string(b)), "0x"), 16, 64); err == nil && a != 0 {
				secs[e.Name()] = a
			}
		}
		if len(secs) > 0 {
			out[m.Name()] = secs
		}
	}
	return out
}

// New builds a Resolver from kallsyms-formatted text and, optionally,
// /proc/modules text, module sections and /proc/vmallocinfo text.
func New(kallsyms, modules io.Reader, sections map[string]map[string]uint64, vmallocinfo io.Reader) (*Resolver, error) {
	r := &Resolver{byName: map[string][]uint64{}, modules: map[string]*ModuleInfo{}}
	if err := r.parseKallsyms(kallsyms); err != nil {
		return nil, err
	}
	if modules != nil {
		mods, err := ParseModules(modules)
		if err != nil {
			return nil, fmt.Errorf("reading /proc/modules: %w", err)
		}
		for i := range mods {
			m := mods[i]
			r.modules[m.Name] = &m
			if m.Base != 0 {
				r.anchors = append(r.anchors, symbol{m.Base, "", Module, m.Name})
			}
		}
	}
	for mod, secs := range sections {
		for name, a := range secs {
			if strings.HasPrefix(name, ".init") || strings.HasPrefix(name, ".exit") {
				continue // freed after loading
			}
			r.anchors = append(r.anchors, symbol{a, "", Module, mod})
		}
	}
	if vmallocinfo != nil {
		areas, err := ParseVmallocinfo(vmallocinfo)
		if err == nil {
			r.areas = areas
		}
	}
	sort.Slice(r.core, func(i, j int) bool { return less(r.core[i], r.core[j]) })
	sort.Slice(r.anchors, func(i, j int) bool { return less(r.anchors[i], r.anchors[j]) })
	return r, nil
}

func less(a, b symbol) bool {
	if a.addr != b.addr {
		return a.addr < b.addr
	}
	// Named symbols first, then by name, so lookups report a name.
	if (a.name == "") != (b.name == "") {
		return a.name != ""
	}
	return a.name < b.name
}

func (r *Resolver) parseKallsyms(rd io.Reader) error {
	syms := map[string]uint64{}
	nonZero := false
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || len(f) > 4 {
			continue
		}
		addr, err := strconv.ParseUint(f[0], 16, 64)
		if err != nil {
			continue
		}
		if addr != 0 {
			nonZero = true
		}
		name := f[2]
		if len(f) == 3 {
			r.core = append(r.core, symbol{addr, name, Kernel, ""})
			r.byName[name] = append(r.byName[name], addr)
			syms[name] = addr
			continue
		}
		tag := strings.TrimSuffix(strings.TrimPrefix(f[3], "["), "]")
		s := symbol{addr: addr, name: name}
		switch {
		case tag == "bpf" || strings.HasPrefix(tag, "__builtin__bpf"):
			s.kind = BPF
		case strings.HasPrefix(tag, "__builtin__ftrace"):
			s.kind = Ftrace
		case strings.HasPrefix(tag, "__builtin__kprobes"):
			s.kind = Kprobe
		case strings.HasPrefix(tag, "__builtin__"):
			continue // other kernel-generated regions: not attributed
		default:
			s.kind, s.owner = Module, tag
		}
		r.anchors = append(r.anchors, s)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("reading kallsyms: %w", err)
	}
	if len(r.core) == 0 {
		return errors.New("no kernel symbols in /proc/kallsyms")
	}
	if !nonZero {
		return ErrAddressesHidden
	}
	first := func(names ...string) uint64 {
		for _, n := range names {
			if a, ok := syms[n]; ok && a != 0 {
				return a
			}
		}
		return 0
	}
	r.textStart = first("_stext")
	if t := first("_text"); t != 0 && (r.textStart == 0 || t < r.textStart) {
		r.textStart = t
	}
	r.textEnd = first("_etext")
	r.initStart, r.initEnd = first("_sinittext"), first("_einittext")
	r.imageEnd = first("_end")
	if r.textStart == 0 || r.textEnd <= r.textStart {
		return errors.New("_stext/_etext missing from /proc/kallsyms")
	}
	if r.imageEnd < r.textEnd {
		r.imageEnd = r.textEnd
	}
	return nil
}

// ParseModules parses /proc/modules: "name size refcnt used_by state address".
func ParseModules(rd io.Reader) ([]ModuleInfo, error) {
	var out []ModuleInfo
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 6 {
			continue
		}
		m := ModuleInfo{Name: f[0]}
		m.Size, _ = strconv.ParseUint(f[1], 10, 64)
		m.Base, _ = strconv.ParseUint(strings.TrimPrefix(f[5], "0x"), 16, 64)
		for _, u := range strings.Split(strings.TrimSuffix(f[3], ","), ",") {
			if u != "" && u != "-" {
				m.UsedBy = append(m.UsedBy, u)
			}
		}
		out = append(out, m)
	}
	return out, sc.Err()
}

// ParseVmallocinfo parses /proc/vmallocinfo lines:
// "0xffffffffc0000000-0xffffffffc0005000   20480 load_module+0x1b4/0x2010 pages=4 vmalloc N0=4".
// It returns an error if addresses are hidden.
func ParseVmallocinfo(rd io.Reader) ([]Area, error) {
	var out []Area
	nonZero := false
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		lo, hi, ok := strings.Cut(f[0], "-")
		if !ok {
			continue
		}
		start, err1 := strconv.ParseUint(strings.TrimPrefix(lo, "0x"), 16, 64)
		end, err2 := strconv.ParseUint(strings.TrimPrefix(hi, "0x"), 16, 64)
		if err1 != nil || err2 != nil || end <= start {
			continue
		}
		nonZero = true
		a := Area{Start: start, End: end}
		if len(f) > 2 && !strings.Contains(f[2], "=") {
			a.Caller, _, _ = strings.Cut(f[2], "+")
		}
		out = append(out, a)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !nonZero {
		return nil, errors.New("/proc/vmallocinfo addresses are hidden")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out, nil
}

// Precise reports whether allocation ranges (/proc/vmallocinfo) were
// available. Without them, module ownership is inferred from distances to
// the nearest module symbol, which is coarser.
func (r *Resolver) Precise() bool { return len(r.areas) > 0 }

// InText reports whether addr is in the core kernel's text.
func (r *Resolver) InText(addr uint64) bool {
	return (addr >= r.textStart && addr < r.textEnd) ||
		(r.initStart != 0 && addr >= r.initStart && addr < r.initEnd)
}

// InImage reports whether addr is in the core kernel image (text, data, bss).
func (r *Resolver) InImage(addr uint64) bool {
	return addr >= r.textStart && addr < r.imageEnd
}

// Modules returns the visible modules by name.
func (r *Resolver) Modules() map[string]*ModuleInfo { return r.modules }

// Uses returns the modules m depends on: those listing m as a user.
func (r *Resolver) Uses(m string) []string {
	var out []string
	for name, info := range r.modules {
		for _, u := range info.UsedBy {
			if u == m {
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// CoreAddrs returns the addresses /proc/kallsyms gives for a core kernel
// symbol, including LTO-renamed copies ("name.llvm.<hash>").
func (r *Resolver) CoreAddrs(name string) []uint64 {
	out := append([]uint64(nil), r.byName[name]...)
	prefix := name + ".llvm."
	for n, addrs := range r.byName {
		if strings.HasPrefix(n, prefix) {
			out = append(out, addrs...)
		}
	}
	return out
}

// Distance caps used without /proc/vmallocinfo.
const (
	maxModuleGap = 1 << 20 // module sections and symbols are dense
	maxBPFGap    = 64 << 10
	maxTrampGap  = 8 << 10
)

// Attribute says who owns addr.
func (r *Resolver) Attribute(addr uint64) Attribution {
	if addr == 0 {
		return Attribution{}
	}
	if r.InText(addr) {
		return r.coreSym(Kernel, addr)
	}
	if r.InImage(addr) {
		return r.coreSym(KernelData, addr)
	}
	if r.Precise() {
		return r.attributeArea(addr)
	}
	return r.attributeNearest(addr)
}

func (r *Resolver) coreSym(k Kind, addr uint64) Attribution {
	a := Attribution{Kind: k}
	i := sort.Search(len(r.core), func(i int) bool { return r.core[i].addr > addr })
	if i > 0 {
		// Prefer the alphabetically first alias at that address.
		j := i - 1
		for j > 0 && r.core[j-1].addr == r.core[i-1].addr {
			j--
		}
		a.Symbol, a.Offset = r.core[j].name, addr-r.core[j].addr
	}
	return a
}

// nearest returns the index of the last anchor at or below addr within
// [lo, hi), or -1. Among anchors at the same address, it prefers named ones.
func (r *Resolver) nearest(addr uint64, lo, hi int) int {
	i := sort.Search(hi-lo, func(i int) bool { return r.anchors[lo+i].addr > addr }) + lo
	if i == lo {
		return -1
	}
	j := i - 1
	for j > lo && r.anchors[j-1].addr == r.anchors[j].addr {
		j--
	}
	return j
}

func (r *Resolver) fromAnchor(s symbol, addr uint64) Attribution {
	a := Attribution{Kind: s.kind, Module: s.owner}
	if s.name != "" {
		a.Symbol, a.Offset = s.name, addr-s.addr
	}
	return a
}

// symbolFor finds the nearest named non-core symbol at or below addr in
// [lo, hi), for reporting.
func (r *Resolver) symbolFor(a *Attribution, addr uint64, lo, hi int) {
	for j := r.nearest(addr, lo, hi); j >= lo && j >= 0; j-- {
		if r.anchors[j].name != "" {
			if r.anchors[j].kind == a.Kind && r.anchors[j].owner == a.Module {
				a.Symbol, a.Offset = r.anchors[j].name, addr-r.anchors[j].addr
			}
			return
		}
	}
}

func (r *Resolver) attributeArea(addr uint64) Attribution {
	i := sort.Search(len(r.areas), func(i int) bool { return r.areas[i].End > addr })
	if i == len(r.areas) || r.areas[i].Start > addr {
		return Attribution{} // not in any allocation: heap, or hidden from vmallocinfo
	}
	area := r.areas[i]
	lo := sort.Search(len(r.anchors), func(i int) bool { return r.anchors[i].addr >= area.Start })
	hi := sort.Search(len(r.anchors), func(i int) bool { return r.anchors[i].addr >= area.End })
	if hi > lo {
		// Shared areas (BPF program packs, execmem caches) hold several
		// owners: the nearest anchor below the address owns it.
		j := r.nearest(addr, lo, hi)
		if j < 0 {
			j = lo
		}
		a := r.fromAnchor(r.anchors[j], addr)
		if a.Symbol == "" {
			r.symbolFor(&a, addr, lo, hi)
		}
		return a
	}
	// No symbol inside: BPF symbols are hidden when
	// net.core.bpf_jit_kallsyms=0, so trust the allocator's name.
	c := area.Caller
	switch {
	case strings.Contains(c, "bpf"):
		return Attribution{Kind: BPF}
	case strings.Contains(c, "kprobe") || strings.Contains(c, "insn_page"):
		return Attribution{Kind: Kprobe}
	case strings.Contains(c, "ftrace"):
		return Attribution{Kind: Ftrace}
	}
	return Attribution{}
}

func (r *Resolver) attributeNearest(addr uint64) Attribution {
	for _, m := range r.modules {
		if m.Base != 0 && addr >= m.Base && addr < m.Base+m.Size {
			a := Attribution{Kind: Module, Module: m.Name}
			r.symbolFor(&a, addr, 0, len(r.anchors))
			return a
		}
	}
	j := r.nearest(addr, 0, len(r.anchors))
	if j < 0 {
		return Attribution{}
	}
	s := r.anchors[j]
	gap := addr - s.addr
	limit := uint64(maxModuleGap)
	switch s.kind {
	case BPF:
		limit = maxBPFGap
	case Ftrace, Kprobe:
		limit = maxTrampGap
	}
	if gap >= limit {
		return Attribution{}
	}
	a := r.fromAnchor(s, addr)
	if a.Symbol == "" {
		r.symbolFor(&a, addr, 0, len(r.anchors))
	}
	return a
}
