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

	type check struct {
		syscall
		symbol   string
		expected uint64
	}
	var checks []check
	for _, s := range watched {
		sym, addr, ok := handler(ks, s.name)
		if !ok {
			rec.Log().Debug("no handler symbol, skipping", "syscall", s.name)
			continue
		}
		checks = append(checks, check{s, sym, addr})
	}
	if len(checks) > maxEntries {
		return fmt.Errorf("too many syscalls to check (%d > %d)", len(checks), maxEntries)
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
	if len(checks) > 0 && actual[0] == 0 {
		return fmt.Errorf("the kprobe on getuid() never fired")
	}

	hooked := 0
	for i, c := range checks {
		if actual[i] == c.expected {
			continue
		}
		hooked++
		rec.Suspicious(fmt.Sprintf("sys_call_table[%d] (%s) points to %#x instead of %s", c.nr, c.name, actual[i], c.symbol),
			map[string]string{
				"syscall":          c.name,
				"syscall_number":   strconv.Itoa(int(c.nr)),
				"expected_symbol":  c.symbol,
				"expected_address": fmt.Sprintf("%#x", c.expected),
				"actual_address":   fmt.Sprintf("%#x", actual[i]),
			})
	}

	if hooked > 0 {
		rec.Message("%d of %d checked syscall table entries are hooked", hooked, len(checks))
	} else {
		rec.Message("All %d checked syscall table entries are intact", len(checks))
	}
	return nil
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
