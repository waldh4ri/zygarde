// Package inlinehook detects kernel functions whose first instructions were
// patched to jump elsewhere, without going through ftrace or kprobes.
package inlinehook

//go:generate go tool bpf2go -target amd64,arm64 -cflags "-Wall -Werror -Wno-missing-declarations" -type func_code inlinehook inlinehook.bpf.c -- -I../../bpf/include

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/kernel"
)

const maxFuncs = 64 // MAX_FUNCS in inlinehook.bpf.c

// canarySymbol is where the reader's kprobe is attached (sys_getuid).
const canarySymbol = "__x64_sys_getuid"

// hotPaths are functions rootkits hook to hide files, processes, connections
// and modules: syscall handlers, directory listing, /proc, the /proc/net show
// functions, and module loading. Reptile-family rootkits (khook) patch
// several of these directly.
var hotPaths = []string{
	"__x64_sys_getdents64", "__x64_sys_getdents", "__x64_sys_kill", "__x64_sys_bpf",
	"__x64_sys_openat", "__x64_sys_read", "__x64_sys_ptrace", "__x64_sys_recvmsg",
	"__x64_sys_init_module", "__x64_sys_finit_module", "__x64_sys_delete_module", "__x64_sys_execve",
	"filldir64", "filldir", "fillonedir", "iterate_dir",
	"proc_pid_readdir", "proc_root_readdir", "proc_pid_lookup", "proc_root_lookup", "next_tgid",
	"vfs_read", "vfs_statx", "do_sys_openat2", "__d_lookup", "__d_lookup_rcu",
	"tcp4_seq_show", "tcp6_seq_show", "udp4_seq_show", "udp6_seq_show",
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
//
// On x86-64, a function starts with an optional endbr64 and a 5-byte ftrace
// site: a NOP when unused, or a call to ftrace (or to a trampoline) when
// hooked through ftrace, which enabled_functions then lists. A jump in that
// place sends every call elsewhere: an inline hook (khook, used by Reptile
// and Mélofée). A call that ftrace doesn't account for is one too.
type Cell struct{}

// New returns the inline hook Cell.
func New() *Cell { return &Cell{} }

func (*Cell) ID() string             { return "inline_hook" }
func (*Cell) Name() string           { return "Inline Hook Detection" }
func (*Cell) Timeout() time.Duration { return 15 * time.Second }
func (*Cell) Description() string {
	return "Reads the first instructions of syscall handlers and VFS, /proc and /proc/net functions and flags jumps out of the kernel's text"
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
		return core.Skip("kernel symbols unavailable: %v", err)
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
	stext, _ := ks.Addr("_stext")
	etext, _ := ks.Addr("_etext")
	inText := func(a uint64) bool { return a >= stext && a < etext }

	var funcs []function
	for _, name := range hotPaths {
		sym := name
		if !ks.Has(sym) {
			var ok bool
			if sym, ok = ks.FirstWithPrefix(name + "."); !ok {
				continue // not in this kernel, or in a module
			}
		}
		addr, _ := ks.Addr(sym)
		funcs = append(funcs, function{name, sym, addr})
	}
	if len(funcs) > maxFuncs-1 {
		funcs = funcs[:maxFuncs-1]
	}
	if len(funcs) == 0 {
		return core.Skip("none of the checked functions is in /proc/kallsyms")
	}
	// Canary: the reader runs from a kprobe on getuid's handler, so that
	// function's entry must show the patch the kprobe made (an ftrace call,
	// or an int3 without ftrace) at the moment it is read.
	canaryAddr, haveCanary := ks.Addr(canarySymbol)
	if haveCanary {
		funcs = append(funcs, function{canarySymbol, canarySymbol, canaryAddr})
	}

	code, err := readCode(env, funcs)
	if err != nil {
		return err
	}
	if haveCanary {
		last := len(funcs) - 1
		e := decodeEntry(code[last], canaryAddr)
		rec.Canary("kprobe on "+canarySymbol, "first instructions read from kernel memory", e.Kind == entryCall || e.Kind == entryInt3)
		funcs, code = funcs[:last], code[:last]
	}

	traced, tracedErr := enabledFunctions()
	if tracedErr != nil {
		rec.Limit("Calls at ftrace sites not checked against ftrace's own list (%v)", tracedErr)
	}

	// An anomaly might be ftrace patching the site right now: re-read once
	// and keep only what is still there.
	var again [][]byte

	checked, hooked := 0, 0
	unknown := []string{}
	for i, f := range funcs {
		e := decodeEntry(code[i], f.addr)
		suspicious, observe, why := judge(e, f, ks, inText, traced, tracedErr == nil)
		if (suspicious || observe != "") && again == nil {
			if again, err = readCode(env, funcs); err != nil {
				return err
			}
		}
		if suspicious || observe != "" {
			e2 := decodeEntry(again[i], f.addr)
			if e2.Kind != e.Kind || e2.Target != e.Target {
				continue // changed between reads: ftrace at work
			}
		}
		checked++
		details := map[string]string{
			"function": f.sym,
			"address":  fmt.Sprintf("%#x", f.addr),
			"bytes":    fmt.Sprintf("% x", code[i]),
			"entry":    e.Kind.String(),
		}
		if e.Target != 0 {
			details["target"] = fmt.Sprintf("%#x", e.Target)
			if name, off, ok := ks.Lookup(e.Target); ok && inText(e.Target) {
				details["target_symbol"] = fmt.Sprintf("%s+%#x", name, off)
			} else {
				details["target_symbol"] = "outside the kernel's text (module, BPF or allocated memory)"
			}
		}
		switch {
		case suspicious:
			hooked++
			rec.Suspicious(core.Finding{
				Description: fmt.Sprintf("%s starts with %s", f.sym, why),
				Details:     details,
				Why: "The kernel only ever writes a NOP or an ftrace call at the start of these functions. A jump " +
					"there diverts every call to other code before the function runs: an inline hook, the way " +
					"Reptile-family rootkits hide files, processes and connections without ftrace or kprobes.",
				Benign: "Very rare: some security products and old live-patching tools patch functions directly. " +
					"Check which module owns the target address.",
			})
		case observe != "":
			rec.Observe(fmt.Sprintf("%s starts with %s", f.sym, observe), details)
		case e.Kind == entryUnknown:
			unknown = append(unknown, f.sym)
		}
	}
	if len(unknown) > 0 {
		rec.Limit("Entry of %d function(s) not recognised (no ftrace site): %s", len(unknown), strings.Join(unknown, ", "))
	}

	if hooked > 0 {
		rec.Message("%d of %d checked functions are inline-hooked", hooked, checked)
	} else {
		rec.Message("No inline hooks in %d checked functions", checked)
	}
	return nil
}

// judge decides what an entry means. It returns whether it is suspicious,
// or an observation to record, with a phrase describing the entry.
func judge(e entry, f function, ks *kernel.Kallsyms, inText func(uint64) bool, traced map[string]bool, haveTraced bool) (bool, string, string) {
	target := fmt.Sprintf("%#x", e.Target)
	if name, off, ok := ks.Lookup(e.Target); ok && inText(e.Target) {
		target = fmt.Sprintf("%s+%#x", name, off)
	}
	switch e.Kind {
	case entryJump:
		if !inText(e.Target) {
			return true, "", "a jump out of the kernel's text, to " + target
		}
		return false, "a jump to " + target + " inside the kernel's text", ""
	case entryIndirect:
		return true, "", "an indirect jump through memory"
	case entryCall:
		name, off, ok := ks.Lookup(e.Target)
		if ok && off == 0 && ftraceTargets[name] && inText(e.Target) {
			return false, "", "" // ftrace's own handler; hook_inventory lists the hook
		}
		if !haveTraced {
			return false, "a call to " + target + " (not verified against ftrace)", ""
		}
		if traced[f.sym] || traced[f.name] {
			return false, "", "" // an ftrace or BPF trampoline, listed by ftrace
		}
		return true, "", "a call to " + target + " that ftrace did not place there"
	case entryInt3:
		return false, "a breakpoint (int3), e.g. a kprobe not using ftrace", ""
	}
	return false, "", ""
}

// readCode triggers the BPF reader and returns the first bytes of each function.
func readCode(env *core.Env, funcs []function) ([][]byte, error) {
	spec, err := loadInlinehook()
	if err != nil {
		return nil, err
	}
	if err := bpfutil.SetTarget(env, spec); err != nil {
		return nil, err
	}
	var addrs [maxFuncs]uint64
	for i, f := range funcs {
		addrs[i] = f.addr
	}
	if err := bpfutil.SetVariable(spec, "nr_funcs", uint32(len(funcs))); err != nil {
		return nil, err
	}
	if err := bpfutil.SetVariable(spec, "addrs", addrs); err != nil {
		return nil, err
	}
	var objs inlinehookObjects
	if err := bpfutil.Load(env, spec, &objs); err != nil {
		return nil, err
	}
	defer objs.Close()

	// cilium/ebpf adds the architecture prefix (__x64_sys_getuid).
	kp, err := link.Kprobe("sys_getuid", objs.ReadCode, nil)
	if err != nil {
		return nil, core.WrapBPF("attach kprobe sys_getuid", err)
	}
	defer kp.Close()

	out := make([][]byte, len(funcs))
	for attempt := 0; attempt < 3; attempt++ {
		unix.Getuid() // a real syscall: Go doesn't cache getuid
		var c inlinehookFuncCode
		if err := objs.Prologues.Lookup(uint32(0), &c); err != nil {
			return nil, core.WrapBPF("read prologues map", err)
		}
		if c.Bytes != [16]uint8{} {
			break
		}
	}
	for i := range funcs {
		var c inlinehookFuncCode
		if err := objs.Prologues.Lookup(uint32(i), &c); err != nil {
			return nil, core.WrapBPF("read prologues map", err)
		}
		if c.Bytes == [16]uint8{} {
			return nil, errors.New("the kprobe on getuid() never fired")
		}
		out[i] = append([]byte(nil), c.Bytes[:]...)
	}
	return out, nil
}

// enabledFunctions returns the functions ftrace has patched, from
// <tracefs>/enabled_functions.
func enabledFunctions() (map[string]bool, error) {
	dir, cleanup, err := kernel.Tracefs()
	if err != nil {
		return nil, err
	}
	defer cleanup()
	f, err := os.Open(filepath.Join(dir, "enabled_functions"))
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
		out[strings.Fields(line)[0]] = true
	}
	return out, sc.Err()
}
