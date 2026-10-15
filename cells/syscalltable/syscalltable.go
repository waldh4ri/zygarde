// Package syscalltable checks x86_64 sys_call_table entries for hooks.
package syscalltable

//go:generate go tool bpf2go -target amd64,arm64 -cflags "-Wall -Werror -Wno-missing-declarations" syscalltable syscalltable.bpf.c -- -I../../bpf/include

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/kernel"
)

const maxEntries = 64 // MAX_ENTRIES in syscalltable.bpf.c

// syscall is an x86_64 syscall and the handler symbol it should point to.
type syscall struct {
	nr   uint32
	name string // without the __x64_sys_ / sys_ prefix
}

// Syscalls commonly hooked to hide files, processes, network activity or modules.
var watched = []syscall{
	{0, "read"}, {1, "write"}, {4, "newstat"}, {6, "newlstat"},
	{43, "accept"}, {44, "sendto"}, {45, "recvfrom"}, {62, "kill"},
	{78, "getdents"}, {101, "ptrace"}, {140, "getpriority"}, {157, "prctl"},
	{175, "init_module"}, {176, "delete_module"}, {217, "getdents64"},
	{257, "openat"}, {313, "finit_module"},
}

// Cell compares sys_call_table entries read from kernel memory with the
// handler addresses in /proc/kallsyms.
//
// Since Linux 6.9 (backported to 6.8.5, 6.6.26, 6.1.85 and 5.15.154) x86_64
// dispatches syscalls through a switch in x64_sys_call() and no longer reads
// sys_call_table, so hooking the table has no effect there and this Cell skips.
type Cell struct{}

// New returns the syscall table Cell.
func New() *Cell { return &Cell{} }

func (*Cell) ID() string             { return "altered_syscall_table" }
func (*Cell) Name() string           { return "Syscall Table Integrity" }
func (*Cell) Timeout() time.Duration { return 15 * time.Second }
func (*Cell) Description() string {
	return "Compares sys_call_table entries in kernel memory with handler addresses from /proc/kallsyms"
}

func (*Cell) Supported(env *core.Env) error {
	if env.Arch != "amd64" {
		return core.Skip("only implemented for x86_64")
	}
	if env.Lockdown == "confidentiality" {
		return core.Skip("kernel lockdown (confidentiality) forbids reading kernel memory from BPF")
	}
	ks, err := env.Kallsyms()
	if err != nil {
		return fmt.Errorf("reading /proc/kallsyms: %w", err)
	}
	if ks.Has("x64_sys_call") {
		return core.Skip("this kernel dispatches syscalls through x64_sys_call(); sys_call_table is not used")
	}
	if !ks.Has("sys_call_table") {
		return core.Skip("sys_call_table is not in /proc/kallsyms (kernel built without CONFIG_KALLSYMS_ALL)")
	}
	return nil
}

func (*Cell) Run(ctx context.Context, env *core.Env, rec *core.Recorder) error {
	ks, err := env.Kallsyms()
	if err != nil {
		return err
	}
	table, _ := ks.Addr("sys_call_table")
	// BPF only reads addresses inside the kernel image: kallsyms can be
	// filtered, and a bogus address such as the vsyscall page oopses
	// kernels that let bpf_probe_read_kernel() fault on it.
	img, err := ks.Image()
	if err != nil {
		return core.Skip("kernel image range unavailable: %v", err)
	}
	if !img.HasData {
		return core.Skip("the end of the kernel image (_end) is not in /proc/kallsyms")
	}

	type check struct {
		syscall
		symbol   string
		expected uint64
	}
	var checks []check
	outside := 0
	var maxNr uint32
	for _, s := range watched {
		sym, addr, ok := handler(ks, s.name)
		if !ok {
			rec.Log().Debug("no handler symbol, skipping", "syscall", s.name)
			continue
		}
		if !img.InText(addr, 1) {
			outside++
			outsideImage(rec, sym, addr, img)
			continue
		}
		checks = append(checks, check{s, sym, addr})
		maxNr = max(maxNr, s.nr)
	}
	if len(checks) == 0 {
		if outside > 0 {
			rec.Message("kallsyms places %d syscall handler(s) outside the kernel image", outside)
			return nil
		}
		return core.Skip("none of the checked syscall handlers is in /proc/kallsyms")
	}
	if len(checks) > maxEntries {
		return fmt.Errorf("too many syscalls to check (%d > %d)", len(checks), maxEntries)
	}
	if !img.InImage(table, uint64(maxNr+1)*8) {
		outsideImage(rec, "sys_call_table", table, img)
		rec.Message("kallsyms places sys_call_table outside the kernel image; the table was not read")
		return nil
	}

	spec, err := loadSyscalltable()
	if err != nil {
		return err
	}
	var nrs [maxEntries]uint32
	for i, c := range checks {
		nrs[i] = c.nr
	}
	if err := bpfutil.SetTarget(env, spec); err != nil {
		return err
	}
	for name, v := range map[string]any{
		"table_addr": table,
		"nr_count":   uint32(len(checks)),
		"nrs":        nrs,
	} {
		if err := bpfutil.SetVariable(spec, name, v); err != nil {
			return err
		}
	}

	var objs syscalltableObjects
	if err := bpfutil.Load(env, spec, &objs); err != nil {
		return err
	}
	defer objs.Close()

	// cilium/ebpf adds the architecture prefix (__x64_sys_getuid).
	kp, err := link.Kprobe("sys_getuid", objs.ReadTable, nil)
	if err != nil {
		return core.WrapBPF("attach kprobe sys_getuid", err)
	}
	defer kp.Close()

	actual := make([]uint64, len(checks))
	for attempt := 0; attempt < 3; attempt++ {
		unix.Getuid() // a real syscall: Go doesn't cache getuid
		for i := range checks {
			if err := objs.Entries.Lookup(uint32(i), &actual[i]); err != nil {
				return core.WrapBPF("read entries map", err)
			}
		}
		if actual[0] != 0 {
			break
		}
	}
	if actual[0] == 0 {
		return fmt.Errorf("the kprobe on getuid() never fired")
	}

	hooked := 0
	for i, c := range checks {
		if actual[i] == c.expected {
			continue
		}
		hooked++
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("sys_call_table[%d] (%s) points to %#x instead of %s", c.nr, c.name, actual[i], c.symbol),
			Details: map[string]string{
				"syscall":          c.name,
				"syscall_number":   strconv.Itoa(int(c.nr)),
				"expected_symbol":  c.symbol,
				"expected_address": fmt.Sprintf("%#x", c.expected),
				"actual_address":   fmt.Sprintf("%#x", actual[i]),
			},
			Why: "Each syscall table entry points at the kernel's own handler. A different address sends every " +
				"call of this syscall through other code first, which can alter or hide its results.",
			Benign: "Some older security or monitoring modules patch the table. Check which module owns the " +
				"address (grep it in /proc/kallsyms).",
		})
	}

	switch {
	case hooked > 0:
		rec.Message("%d of %d checked syscall table entries are hooked", hooked, len(checks))
	case outside > 0:
		rec.Message("All %d checked syscall table entries are intact; kallsyms places %d handler(s) outside the kernel image", len(checks), outside)
	default:
		rec.Message("All %d checked syscall table entries are intact", len(checks))
	}
	return nil
}

// outsideImage reports a watched symbol that kallsyms places outside the
// kernel image. It is not read.
func outsideImage(rec *core.Recorder, sym string, addr uint64, img kernel.Image) {
	rec.Suspicious(core.Finding{
		Description: fmt.Sprintf("/proc/kallsyms reports %s at %#x, outside the kernel image", sym, addr),
		Details: map[string]string{
			"symbol":       sym,
			"address":      fmt.Sprintf("%#x", addr),
			"kernel_image": fmt.Sprintf("%#x-%#x", img.TextStart, img.End),
		},
		Why: "This symbol is part of the core kernel, so its address must fall between _stext and _end. A different " +
			"address means /proc/kallsyms is being rewritten, which rootkits do to mislead scanners that rely on it.",
		Benign: "None expected.",
	})
}

// handler finds the kallsyms symbol for a syscall's handler.
func handler(ks *kernel.Kallsyms, name string) (string, uint64, bool) {
	for _, sym := range []string{"__x64_sys_" + name, "sys_" + name} {
		if addr, ok := ks.Addr(sym); ok {
			return sym, addr, true
		}
	}
	return "", 0, false
}
