// Package hooks inventories kernel functions hooked through ftrace and kprobes,
// flagging hooks that redirect execution or run code that can't be attributed.
package hooks

//go:generate go tool bpf2go -target amd64,arm64 -cflags "-Wall -Werror -Wno-missing-declarations" hooks hooks.bpf.c -- -I../../bpf/include

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fsutil"
	"github.com/waldh4ri/zygarde/internal/kernel"
)

// canaryCandidates are harmless functions the canary may hook, in order of
// preference. The first one ftrace can patch on this kernel is used: syscall
// wrappers aren't always traceable, and enabled_functions names a function
// by whatever symbol sits at its address.
var canaryCandidates = []string{
	"__x64_sys_getppid", "__arm64_sys_getppid", "__do_sys_getppid", "__se_sys_getppid",
	"__ia32_sys_getppid", "ksys_sync",
}

// Cell reads ftrace's list of patched functions (enabled_functions) and, when
// available, /sys/kernel/debug/kprobes/list.
type Cell struct{}

// New returns the hook inventory Cell.
func New() *Cell { return &Cell{} }

func (*Cell) ID() string             { return "hook_inventory" }
func (*Cell) Name() string           { return "Kernel Hook Inventory" }
func (*Cell) Timeout() time.Duration { return 30 * time.Second }
func (*Cell) Description() string {
	return "Lists functions hooked through ftrace (kprobes, BPF trampolines, ftrace ops) and kprobes/list, flagging unattributed or redirecting hooks"
}

func (*Cell) Supported(env *core.Env) error {
	if env.Lockdown == "confidentiality" {
		return core.Skip("kernel lockdown (confidentiality) forbids access to tracefs")
	}
	return nil
}

func (c *Cell) Run(ctx context.Context, env *core.Env, rec *core.Recorder) error {
	dir, cleanup, err := kernel.Tracefs()
	if errors.Is(err, kernel.ErrNoTracefs) {
		return core.Skip("kernel has no tracefs")
	}
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
	if target == "" {
		rec.Limit("No canary hook could be planted on this kernel, so the hook list itself is unverified")
	}

	f, err := fsutil.OpenNoAtime(path)
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

	livepatched := livepatchedFunctions("/sys/kernel/livepatch")
	hooked, suspicious := 0, 0
	for _, h := range hooks {
		// Only skip the canary function when our canary is the sole hook on it
		// and no execution redirection or unattributed handler is present;
		// otherwise a rootkit co-hooking getppid would hide behind our canary.
		if target != "" && baseName(h.Function) == target && isSoleCanary(h) {
			continue
		}
		hooked++
		if classify(rec, h, livepatched) {
			suspicious++
		}
	}

	suspicious += checkKprobesList(rec, target)

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

func isSoleCanary(h hook) bool {
	if h.RefCount > 1 || (h.Flags['I'] && !bpfDirectOnly(h)) {
		return false
	}
	for _, s := range h.Handlers {
		if unresolved(s) {
			return false
		}
	}
	return true
}

// bpfDirectOnly reports whether h is a lone BPF trampoline attached through
// ftrace's direct_ops. Before Linux 6.0 (commit 53cd885bc5c3), direct_ops was
// registered with FTRACE_OPS_FL_IPMODIFY, so every fentry/fexit/LSM program
// shows the I flag on those kernels without redirecting the function.
func bpfDirectOnly(h hook) bool {
	if h.RefCount != 1 || !h.Flags['D'] || len(h.Direct) == 0 {
		return false
	}
	for _, s := range h.Handlers {
		if baseName(s) != "call_direct_funcs" {
			return false
		}
	}
	for _, d := range h.Direct {
		if !strings.HasPrefix(d, "bpf_trampoline_") {
			return false
		}
	}
	return true
}

// classify records one hooked function and reports whether it is suspicious.
// livepatched holds the exact function names currently patched by kernel livepatch.
func classify(rec *core.Recorder, h hook, livepatched map[string]bool) bool {
	fn := h.Function
	details := map[string]string{
		"function": fn,
		"refcount": strconv.Itoa(h.RefCount),
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
			rec.Suspicious(core.Finding{
				Description: fmt.Sprintf("%s is hooked by code at %s, which belongs to no visible module", fn, s),
				Details:     details,
				Why: "The kernel names hook handlers after the kernel function, module or BPF program they belong " +
					"to. This one has no name, so it runs from memory no visible module or program owns, which is " +
					"typical of a module that hid itself after installing the hook.",
				Benign: "Rare. Check the address against the module list and loaded BPF programs.",
			})
			return true
		}
	}

	if h.Flags['I'] && !bpfDirectOnly(h) {
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
		case !attributed(h.Handlers) && livepatched[baseName(fn)]:
			rec.Observe(fmt.Sprintf("%s has an execution-redirecting hook (accounted for by livepatch)", fn), details)
			return false
		default:
			rec.Suspicious(core.Finding{
				Description: fmt.Sprintf("%s is hooked by an ftrace handler that redirects execution", fn),
				Details:     details,
				Why: "This hook can make the kernel run other code instead of this function (ftrace's IPMODIFY " +
					"flag). Live patches are the only standard use; otherwise it means the function was replaced.",
				Benign: "An out-of-tree live patch or a security product that replaces functions. The handler " +
					"listed above names the module responsible.",
			})
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

// checkKprobesList inspects /sys/kernel/debug/kprobes/list when readable,
// catching jump-optimized kprobes ([OPTIMIZED]) and kprobes at non-entry
// offsets that do not go through ftrace enabled_functions.
func checkKprobesList(rec *core.Recorder, canaryFn string) int {
	f, err := fsutil.OpenNoAtime("/sys/kernel/debug/kprobes/list")
	if err != nil {
		return 0
	}
	defer f.Close()
	return parseKprobesList(rec, f, canaryFn)
}

func parseKprobesList(rec *core.Recorder, r io.Reader, canaryFn string) int {
	suspicious := 0
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		addr, kind, sym := fields[0], fields[1], fields[2]
		if canaryFn != "" && baseName(sym) == canaryFn {
			continue
		}
		flags := strings.Join(fields[3:], " ")
		details := map[string]string{"address": addr, "probe_type": kind, "target": sym}
		if flags != "" {
			details["flags"] = flags
		}
		if unresolved(baseName(sym)) {
			suspicious++
			rec.Suspicious(core.Finding{
				Description: fmt.Sprintf("Kprobe (%s) is registered at unattributed kernel address %s", kind, sym),
				Details:     details,
				Why:         "A kprobe placed on an address with no kernel or visible module symbol points to hidden code or a scrubbed symbol.",
				Benign:      "Rare; check loaded BPF programs and module addresses.",
			})
			continue
		}
		if !strings.Contains(flags, "[FTRACE]") {
			rec.Observe(fmt.Sprintf("Non-ftrace kprobe (%s) on %s %s", kind, sym, flags), details)
		}
	}
	return suspicious
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

// livepatchedFunctions returns the exact set of functions patched by active
// kernel livepatches (/sys/kernel/livepatch/<patch>/<object>/<func[,sympos]>).
// Checking per-function entries prevents a rootkit from hiding an IPMODIFY hook
// on an unrelated syscall merely because livepatch is enabled on the host.
func livepatchedFunctions(root string) map[string]bool {
	funcs := map[string]bool{}
	patches, err := fsutil.ReadDirNoAtime(root)
	if err != nil {
		return funcs
	}
	for _, p := range patches {
		if !p.IsDir() {
			continue
		}
		patchDir := filepath.Join(root, p.Name())
		if b, err := fsutil.ReadFileNoAtime(filepath.Join(patchDir, "enabled")); err == nil && strings.TrimSpace(string(b)) == "0" {
			continue
		}
		objs, err := fsutil.ReadDirNoAtime(patchDir)
		if err != nil {
			continue
		}
		for _, obj := range objs {
			if !obj.IsDir() {
				continue
			}
			fns, err := fsutil.ReadDirNoAtime(filepath.Join(patchDir, obj.Name()))
			if err != nil {
				continue
			}
			for _, fn := range fns {
				if !fn.IsDir() {
					continue
				}
				name, _, _ := strings.Cut(fn.Name(), ",")
				if name != "" {
					funcs[name] = true
				}
			}
		}
	}
	return funcs
}

// canaryTarget returns the first canary candidate that ftrace can patch, or "".
func canaryTarget(tracefs string) string {
	f, err := fsutil.OpenNoAtime(filepath.Join(tracefs, "available_filter_functions"))
	if err != nil {
		return ""
	}
	defer f.Close()
	traceable := make(map[string]bool)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		name, _, _ := strings.Cut(sc.Text(), " ")
		traceable[name] = true
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
				if id, err := bpfutil.ProgramID(p.Prog); err == nil {
					rec.Footprint("canary_bpf_prog_id", strconv.FormatUint(uint64(id), 10))
				}
				rec.Footprint("canary_fentry", target)
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
	if id, err := bpfutil.ProgramID(p.Prog); err == nil {
		rec.Footprint("canary_bpf_prog_id", strconv.FormatUint(uint64(id), 10))
	}
	rec.Footprint("canary_kprobe", target)
	return target, "kprobe", func() { l.Close(); p.Prog.Close() }
}
