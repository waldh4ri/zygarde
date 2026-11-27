// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

// Package inlinehook detects kernel functions whose first instructions were
// patched to jump elsewhere, without going through ftrace or kprobes.
package inlinehook

import (
	"bufio"
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fsutil"
	"github.com/waldh4ri/zygarde/internal/kernel"
	"github.com/waldh4ri/zygarde/internal/kmem"
)

// codeBytes is how much of each function entry is read.
const codeBytes = 24

// canarySymbol is where the reader's kprobe is attached (sys_getuid).
const canarySymbol = "__x64_sys_getuid"

// hotPaths are functions rootkits hook to hide files, processes, connections
// and modules: syscall dispatchers & handlers, directory listing, /proc, the
// /proc/net and sock_diag handlers, and module/cred/audit hooks.
var hotPaths = []string{
	"x64_sys_call", "do_syscall_64",
	"__x64_sys_getdents64", "__x64_sys_getdents", "__x64_sys_kill", "__x64_sys_bpf",
	"__x64_sys_openat", "__x64_sys_read", "__x64_sys_ptrace", "__x64_sys_recvmsg",
	"__x64_sys_init_module", "__x64_sys_finit_module", "__x64_sys_delete_module", "__x64_sys_execve",
	"filldir64", "filldir", "fillonedir", "iterate_dir",
	"proc_pid_readdir", "proc_root_readdir", "proc_pid_lookup", "proc_root_lookup", "next_tgid",
	"vfs_read", "vfs_statx", "do_sys_openat2", "__d_lookup", "__d_lookup_rcu",
	"tcp4_seq_show", "tcp6_seq_show", "udp4_seq_show", "udp6_seq_show", "raw_seq_show", "packet_seq_show",
	"inet_diag_handler_cmd", "tcp_diag_dump",
	"inet_ioctl", "packet_rcv", "tpacket_rcv",
	"load_elf_binary", "copy_creds", "commit_creds", "audit_alloc", "do_init_module",
}

// ftraceTargets are the kernel's own handlers an active ftrace site calls.
var ftraceTargets = map[string]bool{
	"__fentry__": true, "ftrace_caller": true, "ftrace_regs_caller": true, "ftrace_stub": true,
	"ftrace_stub_direct_tramp": true,
}

// Cell reads the first bytes of the functions on rootkits' hot paths and
// checks them against what the kernel itself writes there.
type Cell struct{}

// New returns the inline hook Cell.
func New() *Cell { return &Cell{} }

func (*Cell) ID() string             { return "inline_hook" }
func (*Cell) Name() string           { return "Inline Hook Detection" }
func (*Cell) Timeout() time.Duration { return 15 * time.Second }
func (*Cell) Description() string {
	return "Reads the first instructions of syscall handlers and VFS, /proc and /proc/net functions and flags jumps out of the kernel's text or overwritten ftrace sites"
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
		return core.SkipSymbols(err)
	}
	for _, s := range []string{"_stext", "_etext"} {
		if !ks.Has(s) {
			return core.Skip("%s is not in /proc/kallsyms", s)
		}
	}
	return nil
}

type function struct {
	name string // as requested
	sym  string // kallsyms name (LTO builds may add a suffix)
	addr uint64
}

func (*Cell) Run(ctx context.Context, env *core.Env, rec *core.Recorder) error {
	ks, err := env.Kallsyms()
	if err != nil {
		return err
	}
	// BPF only reads addresses inside the kernel's text: kallsyms can be
	// filtered, and a bogus address such as the vsyscall page oopses
	// kernels that let bpf_probe_read_kernel() fault on it.
	img, err := ks.Image()
	if err != nil {
		return core.Skip("kernel image range unavailable: %v", err)
	}
	inText := func(a uint64) bool { return img.InText(a, 1) }

	var funcs []function
	outside := 0
	for _, name := range hotPaths {
		sym := name
		if !ks.Has(sym) {
			var ok bool
			if sym, ok = ks.FirstWithPrefix(name + "."); !ok {
				continue // not in this kernel, or in a module
			}
		}
		addr, _ := ks.Addr(sym)
		if !img.InText(addr, codeBytes) {
			outside++
			outsideImage(rec, sym, addr, img)
			continue
		}
		funcs = append(funcs, function{name, sym, addr})
	}
	if len(funcs) == 0 {
		if outside > 0 {
			rec.Message("kallsyms places %d checked function(s) outside the kernel's text", outside)
			return nil
		}
		return core.Skip("none of the checked functions is in /proc/kallsyms")
	}
	// Canary: the reader runs from a kprobe on getuid's handler, so that
	// function's entry must show the patch the kprobe made (an ftrace call,
	// or an int3 without ftrace) at the moment it is read.
	canaryAddr, haveCanary := ks.Addr(canarySymbol)
	if haveCanary && !img.InText(canaryAddr, codeBytes) {
		outside++
		outsideImage(rec, canarySymbol, canaryAddr, img)
		haveCanary = false
	}
	if haveCanary {
		funcs = append(funcs, function{canarySymbol, canarySymbol, canaryAddr})
	}

	mem, err := kmem.Open(env)
	if err != nil {
		return err
	}
	defer mem.Close()
	if id := mem.ProgramID(); id != 0 {
		rec.Footprint("bpf_prog_id", strconv.FormatUint(uint64(id), 10))
	}
	code, err := readCode(mem, funcs)
	if err != nil {
		return err
	}
	if haveCanary {
		last := len(funcs) - 1
		if code[last] != nil {
			e := decodeEntry(code[last], canaryAddr)
			rec.Canary("kprobe on "+canarySymbol, "first instructions read from kernel memory", e.Kind == entryCall || e.Kind == entryInt3)
		} else {
			rec.Canary("kprobe on "+canarySymbol, "first instructions read from kernel memory", false)
		}
		funcs, code = funcs[:last], code[:last]
	}

	traced, filterable, tracedErr := tracefsState()
	if tracedErr != nil {
		rec.Limit("Calls at ftrace sites not checked against ftrace's own list (%v)", tracedErr)
	}

	// An anomaly might be ftrace patching the site right now: re-read once
	// and keep only what is still there.
	var again [][]byte

	checked, hooked := 0, 0
	unknown := []string{}
	for i, f := range funcs {
		if code[i] == nil {
			rec.Limit("Could not read instructions of %s (%#x)", f.sym, f.addr)
			continue
		}
		e := decodeEntry(code[i], f.addr)
		hasFtraceSite := filterable != nil && (filterable[f.sym] || filterable[f.name])
		suspicious, observe, why := judge(e, f, ks, inText, traced, tracedErr == nil, hasFtraceSite)
		if (suspicious || observe != "") && again == nil {
			var err2 error
			if again, err2 = readCode(mem, funcs); err2 != nil {
				return err2
			}
		}
		if suspicious || observe != "" {
			if again[i] == nil {
				continue
			}
			e2 := decodeEntry(again[i], f.addr)
			if e2.Kind != e.Kind || e2.Target != e.Target || e2.PostNop != e.PostNop {
				continue // changed between reads: ftrace at work
			}
		}
		checked++
		details := map[string]string{
			"function": f.sym,
			"address":  fmt.Sprintf("%#x", f.addr),
			"bytes":    fmt.Sprintf("% x", code[i]),
			"entry":    e.Kind.String(),
			"offset":   strconv.Itoa(e.Offset),
		}
		if e.Target != 0 {
			details["target"] = fmt.Sprintf("%#x", e.Target)
			if name, off, ok := ks.Lookup(e.Target); ok && inText(e.Target) {
				details["target_symbol"] = fmt.Sprintf("%s+%#x", name, off)
			} else if fn, mod, off, ok := ks.LookupModule(e.Target); ok {
				details["target_symbol"] = fmt.Sprintf("%s+%#x [%s]", fn, off, mod)
			} else {
				details["target_symbol"] = "outside the kernel's text (hidden module, BPF or allocated memory)"
			}
		}
		switch {
		case suspicious:
			hooked++
			rec.Suspicious(core.Finding{
				Description: fmt.Sprintf("%s starts with %s", f.sym, why),
				Details:     details,
				Why: "The kernel only ever writes a NOP or an ftrace call at the start of traceable functions, and " +
					"never jumps out of kernel text right after it. Overwriting the prologue diverts or neuters " +
					"every call without registering in ftrace or kprobes.",
				Benign: "Very rare: some security products and old live-patching tools patch functions directly. " +
					"Check which module owns the target address.",
			})
		case observe != "":
			rec.Observe(fmt.Sprintf("%s starts with %s", f.sym, observe), details)
		case e.Kind == entryUnknown:
			if filterable == nil {
				unknown = append(unknown, f.sym)
			}
		}
	}
	if len(unknown) > 0 {
		rec.Limit("Entry of %d function(s) not recognised (no ftrace site): %s", len(unknown), strings.Join(unknown, ", "))
	}

	switch {
	case hooked > 0:
		rec.Message("%d of %d checked functions are inline-hooked", hooked, checked)
	case outside > 0:
		rec.Message("No inline hooks in %d checked functions; kallsyms places %d outside the kernel's text", checked, outside)
	default:
		rec.Message("No inline hooks in %d checked functions", checked)
	}
	return nil
}

// outsideImage reports a checked function that kallsyms places outside the
// kernel's text. It is not read.
func outsideImage(rec *core.Recorder, sym string, addr uint64, img kernel.Image) {
	rec.Suspicious(core.Finding{
		Description: fmt.Sprintf("/proc/kallsyms reports %s at %#x, outside the kernel's text", sym, addr),
		Details: map[string]string{
			"function":    sym,
			"address":     fmt.Sprintf("%#x", addr),
			"kernel_text": fmt.Sprintf("%#x-%#x", img.TextStart, img.TextEnd),
		},
		Why: "This function is part of the core kernel, so its address must fall between _stext and _etext. A " +
			"different address means /proc/kallsyms is being rewritten, which rootkits do to mislead scanners that rely on it.",
		Benign: "None expected.",
	})
}

func judge(e entry, f function, ks *kernel.Kallsyms, inText func(uint64) bool, traced map[string]bool, haveTraced, hasFtraceSite bool) (bool, string, string) {
	target := fmt.Sprintf("%#x", e.Target)
	if name, off, ok := ks.Lookup(e.Target); ok && inText(e.Target) {
		target = fmt.Sprintf("%s+%#x", name, off)
	} else if fn, mod, off, ok := ks.LookupModule(e.Target); ok {
		target = fmt.Sprintf("%s+%#x [%s]", fn, off, mod)
	}

	if e.PostNop {
		switch e.Kind {
		case entryIndirect:
			return true, "", "an indirect jump immediately after its ftrace NOP"
		case entryJump:
			if !inText(e.Target) || e.Gadget {
				return true, "", "a jump immediately after its ftrace NOP to " + target
			}
		}
		return false, "", ""
	}

	switch e.Kind {
	case entryJump:
		if !inText(e.Target) {
			if haveTraced && (traced[f.sym] || traced[f.name]) {
				return false, "", ""
			}
			return true, "", "a jump out of the kernel's text, to " + target
		}
		if hasFtraceSite || e.Gadget {
			return true, "", "a jump overwriting its ftrace site, to " + target
		}
		return false, "a jump to " + target + " inside the kernel's text", ""
	case entryIndirect:
		return true, "", "an indirect jump through memory"
	case entryCall:
		name, off, ok := ks.Lookup(e.Target)
		if ok && off == 0 && ftraceTargets[name] && inText(e.Target) {
			return false, "", ""
		}
		if !haveTraced {
			return false, "a call to " + target + " (not verified against ftrace)", ""
		}
		if traced[f.sym] || traced[f.name] {
			return false, "", ""
		}
		return true, "", "a call to " + target + " that ftrace did not place there"
	case entryInt3:
		return false, "a breakpoint (int3), e.g. a kprobe not using ftrace", ""
	case entryUnknown:
		if hasFtraceSite {
			return true, "", "non-standard instructions overwriting its ftrace site"
		}
	}
	return false, "", ""
}

// readCode reads the first codeBytes of each function; an entry is nil when
// it could not be read.
func readCode(mem kmem.Memory, funcs []function) ([][]byte, error) {
	reqs := make([]kmem.Req, len(funcs))
	for i, f := range funcs {
		reqs[i] = kmem.Req{Addr: f.addr, Len: codeBytes}
	}
	return mem.Read(reqs)
}

func tracefsState() (traced, filterable map[string]bool, err error) {
	dir, cleanup, err := kernel.Tracefs()
	if err != nil {
		return nil, nil, err
	}
	defer cleanup()

	readFirstCol := func(name string) (map[string]bool, error) {
		f, err := fsutil.OpenNoAtime(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		defer f.Close()
		out := map[string]bool{}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Text()
			if line == "" || line[0] == ' ' || line[0] == '\t' {
				continue
			}
			if f := strings.Fields(line); len(f) > 0 {
				out[f[0]] = true
			}
		}
		return out, sc.Err()
	}

	traced, err = readFirstCol("enabled_functions")
	if err != nil {
		return nil, nil, err
	}
	// Optional: when the list is unreadable filterable stays nil, and
	// unrecognised function entries are reported as a limitation.
	filterable, _ = readFirstCol("available_filter_functions")
	return traced, filterable, nil
}
