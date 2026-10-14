// Package hooks inventories kernel functions hooked through ftrace and flags
// hooks that redirect execution or run code that can't be attributed.
package hooks

//go:generate go tool bpf2go -target amd64,arm64 -cflags "-Wall -Werror -Wno-missing-declarations" hooks hooks.bpf.c -- -I../../bpf/include

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/core"
)

// canaryCandidates are harmless functions the canary may hook, in order of
// preference. The first one ftrace can patch on this kernel is used: syscall
// wrappers aren't always traceable, and enabled_functions names a function
// by whatever symbol sits at its address.
var canaryCandidates = []string{
	"__x64_sys_getppid", "__arm64_sys_getppid", "__do_sys_getppid", "__se_sys_getppid",
	"__ia32_sys_getppid", "ksys_sync",
}

// Cell reads ftrace's list of patched functions (enabled_functions).
//
// On kernels that no longer use sys_call_table, rootkits hook functions
// through ftrace (often redirecting execution, the "I" flag), kprobes or BPF
// trampolines, and all of these appear in that list along with their handler.
// A handler that resolves to no symbol lives in code that is not part of the
// kernel, a visible module or a named BPF program: typically a module that
// removed itself from the module list.
//
// Hooks that are common and legitimate (BPF tracing tools, kprobes, livepatch)
// are reported as observations, not findings.
type Cell struct{}

// New returns the hook inventory Cell.
func New() *Cell { return &Cell{} }

func (*Cell) ID() string             { return "hook_inventory" }
func (*Cell) Name() string           { return "Kernel Hook Inventory" }
func (*Cell) Timeout() time.Duration { return 30 * time.Second }
func (*Cell) Description() string {
	return "Lists functions hooked through ftrace (kprobes, BPF trampolines, ftrace ops) and flags unattributed or redirecting hooks"
}

func (*Cell) Supported(env *core.Env) error {
	if env.Lockdown == "confidentiality" {
		return core.Skip("kernel lockdown (confidentiality) forbids access to tracefs")
	}
	return nil
}

func (c *Cell) Run(ctx context.Context, env *core.Env, rec *core.Recorder) error {
	dir, cleanup, err := tracefs()
	if err != nil {
		return err
	}
	defer cleanup()
	path := filepath.Join(dir, "enabled_functions")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return core.Skip("kernel built without dynamic ftrace (no enabled_functions)")
	}

	target, kind, closeCanary := plantCanary(env, rec, canaryTarget(dir))
	defer closeCanary()

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	hooks, err := parseEnabledFunctions(f)
	f.Close()
	if err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	if target != "" {
		seen := false
		for _, h := range hooks {
			if baseName(h.Function) == target && (h.Flags['D'] || strings.Contains(strings.Join(h.Handlers, " "), "kprobe_ftrace_handler")) {
				seen = true
			}
		}
		rec.Canary(kind+" hook on "+target, "ftrace enabled_functions", seen)
	}

	livepatch := livepatchActive()
	hooked, suspicious := 0, 0
	for _, h := range hooks {
		if target != "" && baseName(h.Function) == target {
			continue // our own canary
		}
		hooked++
		if classify(rec, h, livepatch) {
			suspicious++
		}
	}

	switch {
	case suspicious > 0:
		rec.Message("%d suspicious hook(s) among %d hooked functions", suspicious, hooked)
	case hooked == 0:
		rec.Message("No kernel functions are hooked through ftrace")
	default:
		rec.Message("%d hooked function(s), all attributed to known mechanisms", hooked)
	}
	return nil
}

// classify records one hooked function and reports whether it is suspicious.
func classify(rec *core.Recorder, h hook, livepatch bool) bool {
	fn := h.Function
	details := map[string]string{
		"function": fn,
		"flags":    flagString(h.Flags),
	}
	if len(h.Handlers) > 0 {
		details["handlers"] = strings.Join(h.Handlers, ", ")
	}
	if len(h.Direct) > 0 {
		details["direct"] = strings.Join(h.Direct, ", ")
	}

	for _, s := range h.Handlers {
		if unresolved(s) {
			details["technique"] = "hook handler outside the kernel, visible modules and named BPF programs (hidden module?)"
			rec.Suspicious(fmt.Sprintf("%s is hooked by code at %s, which belongs to no visible module", fn, s), details)
			return true
		}
	}

	if h.Flags['I'] {
		handlers := strings.Join(h.Handlers, " ")
		switch {
		case strings.Contains(handlers, "klp_ftrace_handler"):
			rec.Observe(fmt.Sprintf("%s is live-patched", fn), details)
			return false
		case strings.Contains(handlers, "kprobe_ftrace_handler"):
			// kprobes with a post_handler use IPMODIFY ops (kernel/kprobes.c).
			// BPF and perf kprobes don't; these come from kernel code calling
			// register_kprobe(), which enabled_functions can't attribute.
			note := ""
			if isSyscall(fn) {
				note = " on a syscall"
			}
			details["note"] = "kprobe with a post handler, registered by kernel code (module or built-in), not by BPF or perf"
			rec.Observe(fmt.Sprintf("%s has a kernel-registered kprobe%s", fn, note), details)
			return false
		case !attributed(h.Handlers) && livepatch:
			rec.Observe(fmt.Sprintf("%s has an execution-redirecting hook (livepatch is active)", fn), details)
			return false
		default:
			details["technique"] = "ftrace hook redirecting execution (FTRACE_OPS_FL_IPMODIFY; the only legitimate user is livepatch)"
			rec.Suspicious(fmt.Sprintf("%s is hooked by an ftrace handler that redirects execution", fn), details)
			return true
		}
	}

	who := "ftrace"
	switch {
	case h.Flags['D'] || len(h.Direct) > 0:
		who = "a BPF trampoline (fentry/fexit/LSM program)"
	case len(h.Handlers) > 0:
		who = owner(h.Handlers[0]) + " (" + baseName(h.Handlers[0]) + ")"
	}
	for _, d := range h.Direct {
		if unresolved(d) {
			details["note"] = "direct-call target unnamed; BPF symbols are hidden when net.core.bpf_jit_kallsyms=0"
		}
	}
	rec.Observe(fmt.Sprintf("%s is hooked by %s", fn, who), details)
	return false
}

// attributed reports whether any handler names a specific owner rather than
// ftrace's generic list dispatcher.
func attributed(handlers []string) bool {
	for _, h := range handlers {
		if b := baseName(h); b != "ftrace_ops_list_func" && b != "ftrace_ops_assist_func" {
			return true
		}
	}
	return false
}

func flagString(flags map[byte]bool) string {
	var b strings.Builder
	for _, f := range []byte("RIDOM") {
		if flags[f] {
			b.WriteByte(f)
		}
	}
	return b.String()
}

func livepatchActive() bool {
	entries, err := os.ReadDir("/sys/kernel/livepatch")
	return err == nil && len(entries) > 0
}

// canaryTarget returns the first canary candidate that ftrace can patch, or "".
func canaryTarget(tracefs string) string {
	f, err := os.Open(filepath.Join(tracefs, "available_filter_functions"))
	if err != nil {
		return ""
	}
	defer f.Close()
	traceable := make(map[string]bool)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		traceable[sc.Text()] = true
	}
	for _, c := range canaryCandidates {
		if traceable[c] {
			return c
		}
	}
	return ""
}

// plantCanary hooks target with a do-nothing fentry program, or with a kprobe
// where BPF trampolines are unavailable. It returns the hooked function and
// the mechanism used, or "" if neither works on this kernel.
func plantCanary(env *core.Env, rec *core.Recorder, target string) (string, string, func()) {
	nop := func() {}
	if target == "" {
		rec.Log().Debug("canary unavailable: no traceable candidate function")
		return "", "", nop
	}
	spec, err := loadHooks()
	if err != nil {
		rec.Log().Debug("canary unavailable", "err", err)
		return "", "", nop
	}

	if env.BTF != nil {
		spec.Programs["canary_fentry"].AttachTo = target
		var p struct {
			Prog *ebpf.Program `ebpf:"canary_fentry"`
		}
		if err := bpfutil.Load(env, spec, &p); err == nil {
			if l, err := link.AttachTracing(link.TracingOptions{Program: p.Prog}); err == nil {
				return target, "fentry", func() { l.Close(); p.Prog.Close() }
			} else {
				rec.Log().Debug("fentry canary attach failed, trying kprobe", "err", err)
			}
			p.Prog.Close()
		} else {
			rec.Log().Debug("fentry canary unavailable, trying kprobe", "err", err)
		}
	}

	// Only x86_64 reliably implements entry kprobes with ftrace; elsewhere a
	// kprobe canary could be invisible to enabled_functions by design.
	if env.Arch != "amd64" {
		return "", "", nop
	}
	var p struct {
		Prog *ebpf.Program `ebpf:"canary_kprobe"`
	}
	if err := bpfutil.Load(env, spec, &p); err != nil {
		rec.Log().Debug("kprobe canary unavailable", "err", err)
		return "", "", nop
	}
	l, err := link.Kprobe(target, p.Prog, nil)
	if err != nil {
		p.Prog.Close()
		rec.Log().Debug("kprobe canary attach failed", "err", err)
		return "", "", nop
	}
	return target, "kprobe", func() { l.Close(); p.Prog.Close() }
}

// tracefs returns a tracefs directory, mounting one temporarily if needed.
func tracefs() (string, func(), error) {
	nop := func() {}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return "", nop, err
	}
	defer f.Close()
	var debugfs string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// "... <mount point> <options> ... - <fstype> <source> <super options>"
		fields := strings.Fields(sc.Text())
		sep := -1
		for i, fld := range fields {
			if fld == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+1 >= len(fields) || len(fields) < 5 {
			continue
		}
		switch fields[sep+1] {
		case "tracefs":
			return fields[4], nop, nil
		case "debugfs":
			debugfs = fields[4]
		}
	}
	if debugfs != "" {
		if _, err := os.Stat(filepath.Join(debugfs, "tracing", "enabled_functions")); err == nil {
			return filepath.Join(debugfs, "tracing"), nop, nil
		}
	}

	dir, err := os.MkdirTemp("", "zygarde-tracefs-")
	if err != nil {
		return "", nop, err
	}
	if err := unix.Mount("nodev", dir, "tracefs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC|unix.MS_RDONLY, ""); err != nil {
		os.Remove(dir)
		if errors.Is(err, unix.ENODEV) {
			return "", nop, core.Skip("kernel has no tracefs")
		}
		return "", nop, fmt.Errorf("mounting tracefs: %w", err)
	}
	return dir, func() {
		unix.Unmount(dir, 0)
		os.Remove(dir)
	}, nil
}
