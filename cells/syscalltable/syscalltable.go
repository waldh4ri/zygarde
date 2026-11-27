// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

// Package syscalltable checks x86_64 sys_call_table entries for hooks.
package syscalltable

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/kernel"
	"github.com/waldh4ri/zygarde/internal/kmem"
)

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
	{257, "openat"}, {313, "finit_module"}, {321, "bpf"},
}

// Cell compares sys_call_table entries read from kernel memory with the
// handler addresses in /proc/kallsyms.
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
		return core.Skip("kernel lockdown (confidentiality)")
	}
	ks, err := env.Kallsyms()
	if err != nil {
		if skip := core.SymbolsUnavailable(err); !errors.Is(skip, err) {
			return skip
		}
		return fmt.Errorf("reading /proc/kallsyms: %w", err)
	}
	if ks.Has("x64_sys_call") {
		return core.Skip("sys_call_table unused (x64_sys_call())")
	}
	if !ks.Has("sys_call_table") {
		return core.Skip("needs CONFIG_KALLSYMS_ALL (no sys_call_table)")
	}
	return nil
}

func (*Cell) Run(ctx context.Context, env *core.Env, rec *core.Recorder) error {
	ks, err := env.Kallsyms()
	if err != nil {
		return err
	}
	table, _ := ks.Addr("sys_call_table")
	img, err := ks.Image()
	if err != nil {
		return core.Skip("kernel image range unavailable: %v", err)
	}
	if !img.HasData {
		return core.Skip("_end not in /proc/kallsyms")
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
		return core.Skip("no checked handler in /proc/kallsyms")
	}
	if !img.InImage(table, uint64(maxNr+1)*8) {
		outsideImage(rec, "sys_call_table", table, img)
		rec.Message("kallsyms places sys_call_table outside the kernel image; the table was not read")
		return nil
	}

	mem, err := kmem.Open(env)
	if err != nil {
		return err
	}
	defer mem.Close()
	if id := mem.ProgramID(); id != 0 {
		rec.Footprint("bpf_prog_id", strconv.FormatUint(uint64(id), 10))
	}
	slots := make([]uint64, len(checks))
	for i, c := range checks {
		slots[i] = table + uint64(c.nr)*8
	}
	entries, ok, err := kmem.ReadU64s(mem, slots)
	if err != nil {
		return err
	}

	hooked, verified := 0, 0
	for i, c := range checks {
		if !ok[i] {
			rec.Limit("Could not read sys_call_table[%d] (%s)", c.nr, c.name)
			continue
		}
		verified++
		if entries[i] == c.expected {
			continue
		}
		hooked++
		details := map[string]string{
			"syscall":          c.name,
			"syscall_number":   strconv.Itoa(int(c.nr)),
			"expected_symbol":  c.symbol,
			"expected_address": fmt.Sprintf("%#x", c.expected),
			"actual_address":   fmt.Sprintf("%#x", entries[i]),
		}
		if fn, mod, off, ok := ks.LookupModule(entries[i]); ok {
			details["actual_symbol"] = fmt.Sprintf("%s+%#x [%s]", fn, off, mod)
		} else if fn, off, ok := ks.Lookup(entries[i]); ok {
			details["actual_symbol"] = fmt.Sprintf("%s+%#x", fn, off)
		}
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("sys_call_table[%d] (%s) points to %#x instead of %s", c.nr, c.name, entries[i], c.symbol),
			Details:     details,
			Why: "Each syscall table entry points at the kernel's own handler. A different address sends every " +
				"call of this syscall through other code first, which can alter or hide its results.",
			Benign: "Some older security or monitoring modules patch the table. Check which module owns the " +
				"address (grep it in /proc/kallsyms).",
		})
	}

	switch {
	case hooked > 0:
		rec.Message("%d of %d checked syscall table entries are hooked", hooked, verified)
	case outside > 0:
		rec.Message("All %d entries intact (%d outside image)", verified, outside)
	default:
		rec.Message("All %d syscall table entries intact", verified)
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

func handler(ks *kernel.Kallsyms, name string) (string, uint64, bool) {
	for _, sym := range []string{"__x64_sys_" + name, "sys_" + name} {
		if addr, ok := ks.Addr(sym); ok {
			return sym, addr, true
		}
	}
	return "", 0, false
}
