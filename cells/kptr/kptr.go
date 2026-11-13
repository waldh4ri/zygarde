// Package kptr checks the function pointers the kernel calls to serve
// /proc, /proc/net, /sys/module and directory listings: every one must point
// into the kernel or the module that implements the file, and the kernel
// symbol table must agree with what kernel memory holds.
package kptr

//go:generate go tool bpf2go -target amd64,arm64 -cflags "-Wall -Werror -Wno-missing-declarations" -type ops_rec kptr kptr.bpf.c -- -I../../bpf/include

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/kattr"
)

// Flags, as in kptr.bpf.c.
const (
	flagSeq     = 1
	flagPDE     = 2
	flagIterate = 4
)

// target is a file zygarde opens to have the kernel's operations behind it
// read back.
type target struct {
	path string
	dir  bool
	// modules that may implement it besides the filesystem's own module
	// (protocols built as modules provide their /proc/net files).
	modules []string
	// names /proc/kallsyms should give for the tables read (CONFIG_KALLSYMS_ALL).
	symbols map[string][]string
}

func targets(pid int) []target {
	return []target{
		{path: "/proc", dir: true, symbols: map[string][]string{"file_operations": {"proc_root_operations"}}},
		{path: fmt.Sprintf("/proc/%d/status", pid)},
		{path: fmt.Sprintf("/proc/%d/maps", pid)},
		{path: fmt.Sprintf("/proc/%d/mountinfo", pid)},
		{path: fmt.Sprintf("/proc/%d/fd", pid), dir: true},
		{path: "/proc/net/tcp", symbols: map[string][]string{"seq_operations": {"tcp4_seq_ops"}}},
		{path: "/proc/net/tcp6", modules: []string{"ipv6"}},
		{path: "/proc/net/udp"},
		{path: "/proc/net/udp6", modules: []string{"ipv6"}},
		{path: "/proc/net/raw"},
		{path: "/proc/net/raw6", modules: []string{"ipv6"}},
		{path: "/proc/net/unix", modules: []string{"unix"}},
		{path: "/proc/net/packet", modules: []string{"af_packet"}},
		{path: "/proc/modules", symbols: map[string][]string{
			"proc_ops": {"modules_proc_ops", "proc_modules_operations"}, "seq_operations": {"modules_op"}}},
		{path: "/proc/kallsyms", symbols: map[string][]string{
			"proc_ops": {"kallsyms_proc_ops", "kallsyms_operations"}, "seq_operations": {"kallsyms_op"}}},
		{path: "/sys/module", dir: true},
		{path: "/", dir: true},
		{path: "/usr/bin", dir: true},
		{path: "/etc", dir: true},
		{path: "/tmp", dir: true},
	}
}

// canaryPath's seq_file show function must resolve to canaryShow.
const (
	canaryPath = "/proc/net/tcp"
	canaryShow = "tcp4_seq_show"
)

// Cell reads, for files zygarde opens itself, the operation tables the
// kernel dispatches through, from the struct file a BPF task_file iterator
// hands over.
//
// Rootkits hide processes, connections and modules by swapping one pointer
// in these tables (adore-ng's /proc iterate, Snapekit and VoidLink's
// tcp4_seq_show): the original code stays intact, so prologue checks miss it.
// Each pointer must resolve to the core kernel or to the module that
// implements the file; code no visible module owns, or an unrelated module,
// is SUSPICIOUS. So is a table outside kernel and module memory (a copied
// table), and a pointer /proc/kallsyms names differently than kernel memory
// (a filtered symbol table).
type Cell struct{}

// New returns the function pointer integrity Cell.
func New() *Cell { return &Cell{} }

func (*Cell) ID() string             { return "kernel_pointers" }
func (*Cell) Name() string           { return "Function Pointer Integrity" }
func (*Cell) Timeout() time.Duration { return 30 * time.Second }
func (*Cell) Description() string {
	return "Reads the file, seq_file and procfs operation tables behind /proc, /proc/net, /sys/module and system directories and flags pointers into unowned code"
}

func (*Cell) Supported(env *core.Env) error {
	if err := env.RequireBTFType("bpf_iter__task_file", "the BPF task file iterator (Linux 5.8+)"); err != nil {
		return err
	}
	if env.Lockdown == "confidentiality" {
		return core.Skip("kernel lockdown (confidentiality) forbids reading kernel memory from BPF")
	}
	return nil
}

// opened is a target zygarde holds open, with what the kernel showed.
type opened struct {
	target
	fd  int
	rec *kptrOpsRec
}

func (c *Cell) Run(ctx context.Context, env *core.Env, rec *core.Recorder) error {
	res, err := kattr.Load()
	if err != nil {
		return core.Skip("kernel symbols unavailable: %v", err)
	}
	if !res.Precise() {
		rec.Limit("/proc/vmallocinfo unreadable: module ownership inferred from symbol distances, and tables outside known memory are only observations")
	}

	var files []*opened
	defer func() {
		for _, f := range files {
			unix.Close(f.fd)
		}
	}()
	for _, t := range targets(os.Getpid()) {
		// Opened, never read. O_NOFOLLOW and O_NONBLOCK: /tmp and the
		// system directories must not lead anywhere else, nor block.
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if t.dir {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Open(t.path, flags, 0)
		if err != nil {
			rec.Log().Debug("not checked", "path", t.path, "err", err)
			continue
		}
		files = append(files, &opened{target: t, fd: fd})
	}
	if len(files) == 0 {
		return fmt.Errorf("none of the files to check could be opened")
	}

	recs, err := read(env)
	if err != nil {
		return err
	}
	byFD := map[int]*kptrOpsRec{}
	for i := range recs {
		if _, dup := byFD[int(recs[i].Fd)]; !dup {
			byFD[int(recs[i].Fd)] = &recs[i]
		}
	}
	missing := 0
	for _, f := range files {
		if f.rec = byFD[f.fd]; f.rec == nil {
			missing++
		}
	}
	rec.Canary(fmt.Sprintf("%d descriptors opened by zygarde", len(files)), "BPF task_file iterator", missing == 0)

	ch := &checker{res: res, rec: rec}
	for _, f := range files {
		if f.rec != nil {
			ch.check(f)
		}
	}

	if ch.canaryRead {
		rec.Canary(canaryShow, "seq_file operations read from zygarde's "+canaryPath, kattr.BaseName(ch.canary) == canaryShow)
	} else {
		rec.Limit("%s could not be opened, so the canary (its show function is %s) was not checked", canaryPath, canaryShow)
	}
	if ch.symbolsChecked == 0 {
		rec.Limit("Kernel data symbols not in /proc/kallsyms (CONFIG_KALLSYMS_ALL off?): operation tables not cross-checked by name")
	}
	if len(ch.unread) > 0 {
		sort.Strings(ch.unread)
		rec.Limit("Some pointers could not be read: %s", strings.Join(ch.unread, ", "))
	}

	if ch.suspicious > 0 {
		rec.Message("%d suspicious pointer(s) among %d checked in %d operation tables", ch.suspicious, ch.pointers, ch.tables)
	} else {
		rec.Message("%d pointers in %d operation tables of %d files point into the kernel or the module implementing them", ch.pointers, ch.tables, len(files)-missing)
	}
	return nil
}

func read(env *core.Env) ([]kptrOpsRec, error) {
	spec, err := loadKptr()
	if err != nil {
		return nil, err
	}
	var objs kptrObjects
	if err := bpfutil.Load(env, spec, &objs); err != nil {
		return nil, err
	}
	defer objs.Close()
	data, err := bpfutil.ReadIter(objs.DumpOps)
	if err != nil {
		return nil, err
	}
	return bpfutil.Decode[kptrOpsRec](data)
}

// pointer is one value read from kernel memory.
type pointer struct {
	name  string // "file_operations", "seq_operations.show"...
	addr  uint64
	table bool // an operations table rather than code
}

// pointers lists the values read for one file. singleOpen omits the
// seq_operations table's own address: single_open() allocates that table.
func pointers(r *kptrOpsRec, singleOpen bool) []pointer {
	ps := []pointer{{"file_operations", r.FileOps, true}}
	for i, n := range []string{"llseek", "read", "read_iter", "iterate", "iterate_shared", "open"} {
		if i == 3 && r.Flags&flagIterate == 0 {
			continue
		}
		ps = append(ps, pointer{"file_operations." + n, r.FileFn[i], false})
	}
	ps = append(ps, pointer{"inode_operations", r.InodeOps, true},
		pointer{"inode_operations.lookup", r.InodeFn[0], false},
		pointer{"inode_operations.getattr", r.InodeFn[1], false})
	if r.Flags&flagSeq != 0 {
		if !singleOpen {
			ps = append(ps, pointer{"seq_operations", r.SeqOps, true})
		}
		for i, n := range []string{"start", "next", "stop", "show"} {
			ps = append(ps, pointer{"seq_operations." + n, r.SeqFn[i], false})
		}
	}
	if r.Flags&flagPDE != 0 {
		ps = append(ps, pointer{"proc_ops", r.ProcOps, true})
		for i, n := range []string{"proc_open", "proc_read", "proc_read_iter", "proc_lseek"} {
			ps = append(ps, pointer{"proc_ops." + n, r.ProcFn[i], false})
		}
	}
	return ps
}

type checker struct {
	res *kattr.Resolver
	rec *core.Recorder

	pointers, tables, suspicious, symbolsChecked int
	canaryRead                                   bool   // canaryPath was opened and read back
	canary                                       string // symbol of its show function
	unread                                       []string
}

// allowed returns the modules that may own f's code: the filesystem's
// module, the target's own, and the modules those depend on.
func (c *checker) allowed(f *opened) map[string]bool {
	out := map[string]bool{}
	add := func(m string) {
		if m == "" || out[m] {
			return
		}
		out[m] = true
		for _, d := range c.res.Uses(m) {
			out[d] = true
		}
	}
	add(bpfutil.Int8String(f.rec.FsOwner[:]))
	for _, m := range f.modules {
		add(m)
	}
	return out
}

func (c *checker) check(f *opened) {
	r := f.rec
	allowed := c.allowed(f)
	// single_open() files (most /proc/<pid> entries) get a seq_operations
	// table allocated on the heap, filled with the kernel's single_* functions.
	start := c.res.Attribute(r.SeqFn[0])
	singleOpen := start.Kind == kattr.Kernel && kattr.BaseName(start.Symbol) == "single_start"
	ps := pointers(r, singleOpen)

	// The proc_dir_entry union holds the seq_operations its files open
	// with (then equal to the seq_file's), or a single_show function.
	if r.Flags&flagPDE != 0 && r.PdeSeq != 0 && !(r.Flags&flagSeq != 0 && r.PdeSeq == r.SeqOps) {
		table := c.res.Attribute(r.PdeSeq).Kind == kattr.KernelData
		ps = append(ps, pointer{"proc_dir_entry.seq_ops", r.PdeSeq, table})
	}

	if f.path == canaryPath {
		c.canaryRead = true
		if r.Flags&flagSeq != 0 && r.SeqFn[3] != 0 {
			c.canary = c.res.Attribute(r.SeqFn[3]).Symbol
		}
	}
	if r.FileOps == 0 || (r.Flags&flagSeq != 0 && r.SeqOps != 0 && r.SeqFn[3] == 0) {
		c.unread = append(c.unread, f.path)
	}

	for _, p := range ps {
		if p.addr == 0 {
			continue
		}
		c.pointers++
		if p.table {
			c.tables++
		}
		a := c.res.Attribute(p.addr)
		details := map[string]string{
			"file":    f.path,
			"pointer": p.name,
			"address": fmt.Sprintf("%#x", p.addr),
			"owner":   a.Where(),
		}
		if len(allowed) > 0 {
			details["expected_modules"] = strings.Join(sortedKeys(allowed), ", ")
		}
		switch v, why := judge(a, p.table, allowed, c.res.Precise()); v {
		case suspicious:
			c.suspicious++
			c.rec.Suspicious(c.finding(f.path, p, a, why, details))
		case observe:
			c.rec.Observe(fmt.Sprintf("%s of %s %s", p.name, f.path, why), details)
		}
		// Kallsyms consistency: kernel code is only reached at the start of a
		// function, which /proc/kallsyms must name.
		if !p.table && a.Kind == kattr.Kernel && a.Offset != 0 {
			c.suspicious++
			c.rec.Suspicious(core.Finding{
				Description: fmt.Sprintf("%s of %s points inside %s, not at the start of a function", p.name, f.path, a.Where()),
				Details:     details,
				Why: "Operation tables point at the first instruction of a function, and /proc/kallsyms names every " +
					"kernel function. A pointer into the middle of one means either the table was redirected to " +
					"code placed there, or /proc/kallsyms is hiding the symbol at that address.",
				Benign: "None known on upstream kernels; check for out-of-tree kernel patches that strip symbols.",
			})
		}
	}

	for kind, names := range f.symbols {
		var got uint64
		switch kind {
		case "file_operations":
			got = r.FileOps
		case "seq_operations":
			got = r.SeqOps
		case "proc_ops":
			got = r.ProcOps
		}
		if got == 0 {
			continue
		}
		var claimed []uint64
		for _, n := range names {
			claimed = append(claimed, c.res.CoreAddrs(n)...)
		}
		if len(claimed) == 0 {
			continue
		}
		c.symbolsChecked++
		if mismatch(got, claimed) {
			c.suspicious++
			c.rec.Suspicious(core.Finding{
				Description: fmt.Sprintf("/proc/kallsyms disagrees with kernel memory about the %s of %s", kind, f.path),
				Details: map[string]string{
					"file":            f.path,
					"in_memory":       fmt.Sprintf("%#x (%s)", got, c.res.Attribute(got).Where()),
					"kallsyms_names":  strings.Join(names, ", "),
					"kallsyms_values": hexList(claimed),
				},
				Why: "The kernel uses this table to serve the file, and /proc/kallsyms reports the table at another " +
					"address. Either the file's table was replaced, or /proc/kallsyms is being filtered to mislead " +
					"tools that trust it (Singularity sanitises kallsyms).",
				Benign: "None expected: both values come from the running kernel.",
			})
		}
	}
}

func mismatch(got uint64, claimed []uint64) bool {
	for _, a := range claimed {
		if a == got {
			return false
		}
	}
	return true
}

func (c *checker) finding(path string, p pointer, a kattr.Attribution, why string, details map[string]string) core.Finding {
	if p.table {
		return core.Finding{
			Description: fmt.Sprintf("The %s of %s %s", p.name, path, why),
			Details:     details,
			Why: "The kernel's operation tables are constant data in the kernel or in the module implementing the " +
				"file. A table elsewhere is a copy someone installed to redirect some of its functions, the way " +
				"rootkits hook /proc and /proc/net without patching code.",
			Benign: "A security product that wraps file operations. Check which module owns the address.",
		}
	}
	return core.Finding{
		Description: fmt.Sprintf("%s of %s %s", p.name, path, why),
		Details:     details,
		Why: "The kernel calls this pointer to list or read the file. It should point into the kernel or the module " +
			"implementing the file; pointing elsewhere lets the code there filter what userspace sees (hidden " +
			"processes, connections or modules), the pointer-swap technique of adore-ng, Snapekit and VoidLink.",
		Benign: "A security product that wraps file operations. Check which module owns the address.",
	}
}

type verdict int

const (
	ok verdict = iota
	observe
	suspicious
)

// judge decides what an attributed pointer means. coarse attribution
// (precise=false) only observes tables it can't place.
func judge(a kattr.Attribution, table bool, allowed map[string]bool, precise bool) (verdict, string) {
	switch a.Kind {
	case kattr.Kernel:
		return ok, ""
	case kattr.KernelData:
		if table {
			return ok, ""
		}
		return observe, "points into kernel data, not code"
	case kattr.Module:
		if allowed[a.Module] {
			return ok, ""
		}
		return suspicious, fmt.Sprintf("is in module %s, which does not implement this file", a.Module)
	case kattr.BPF, kattr.Ftrace, kattr.Kprobe:
		if table {
			return suspicious, "is in " + a.Kind.String() + " memory, not kernel or module data"
		}
		return observe, "points to a " + a.Kind.String()
	}
	if table {
		if !precise {
			return observe, "is outside kernel and module memory as far as symbols show"
		}
		return suspicious, "is outside kernel and module memory"
	}
	return suspicious, "points to code that belongs to no visible module"
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func hexList(a []uint64) string {
	s := make([]string, len(a))
	for i, v := range a {
		s[i] = fmt.Sprintf("%#x", v)
	}
	return strings.Join(s, ", ")
}
