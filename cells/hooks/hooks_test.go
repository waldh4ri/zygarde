package hooks

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/waldh4ri/zygarde/internal/core"
)

// Shapes taken from t_show() in kernel/trace/ftrace.c.
const sample = `__x64_sys_getppid (1)    D   	tramp: 0xffffffffc0002000 (bpf_trampoline_6442464281+0x0/0x50) ->bpf_trampoline_6442464281+0x0/0x50
	direct-->bpf_trampoline_6442464281+0x0/0x50
do_sys_openat2 (1) R          	tramp: ftrace_regs_caller+0x0/0x70 (kprobe_ftrace_handler+0x0/0x1d0) ->kprobe_ftrace_handler+0x0/0x1d0
cmdline_proc_show (1) R I        	tramp: ftrace_trampoline+0x0/0xf0 [__builtin__ftrace] (klp_ftrace_handler+0x0/0x1c0) ->klp_ftrace_handler+0x0/0x1c0
__x64_sys_kill (1) R I        	tramp: ftrace_trampoline+0x0/0xf0 [__builtin__ftrace] (fh_ftrace_thunk+0x0/0x30 [rootkit]) ->fh_ftrace_thunk+0x0/0x30 [rootkit]
__x64_sys_getdents64 (1) R I        	tramp: 0xffffffffc0004000 (0xffffffffc0a01230) ->0xffffffffc0a01230
__x64_sys_openat (1) R I        	tramp: ftrace_regs_caller+0x0/0x70 (kprobe_ftrace_handler+0x0/0x1d0) ->kprobe_ftrace_handler+0x0/0x1d0
tcp4_seq_show (2) R I        ->ftrace_ops_list_func+0x0/0x200
__do_sys_getppid (1) R I D   	tramp: ftrace_regs_caller+0x0/0x65 (call_direct_funcs+0x0/0x20) ->call_direct_funcs+0x0/0x20
	direct-->bpf_trampoline_30874_0+0x0/0x1000
__x64_sys_read (1) R I D   	tramp: ftrace_regs_caller+0x0/0x65 (call_direct_funcs+0x0/0x20) ->call_direct_funcs+0x0/0x20
	direct-->evil_read+0x0/0x40 [rootkit]
`

func TestParse(t *testing.T) {
	hooks, err := parseEnabledFunctions(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(hooks) != 9 {
		t.Fatalf("parsed %d hooks, want 9: %+v", len(hooks), hooks)
	}
	h := hooks[0]
	if h.Function != "__x64_sys_getppid" || h.RefCount != 1 || !h.Flags['D'] || len(h.Direct) != 1 {
		t.Errorf("BPF trampoline parsed wrong: %+v", h)
	}
	if hooks[6].RefCount != 2 {
		t.Errorf("RefCount = %d, want 2", hooks[6].RefCount)
	}
	if got := hooks[3].Handlers[0]; got != "fh_ftrace_thunk+0x0/0x30 [rootkit]" || owner(got) != "module rootkit" {
		t.Errorf("module handler parsed wrong: %q (%s)", got, owner(got))
	}
	if !unresolved(hooks[4].Handlers[0]) {
		t.Errorf("hex handler not detected as unresolved: %q", hooks[4].Handlers[0])
	}
}

func TestClassify(t *testing.T) {
	hooks, _ := parseEnabledFunctions(strings.NewReader(sample))
	want := map[string]bool{
		"__x64_sys_getppid":    false, // BPF trampoline: inventory
		"do_sys_openat2":       false, // plain kprobe: inventory
		"cmdline_proc_show":    false, // livepatch
		"__x64_sys_kill":       true,  // ftrace IPMODIFY hook from a module
		"__x64_sys_getdents64": true,  // handler in unnamed memory
		"__x64_sys_openat":     false, // kprobe with a post handler: not attributable
		"tcp4_seq_show":        true,  // unattributed IPMODIFY, no livepatch
		"__do_sys_getppid":     false, // BPF trampoline on <6.0: direct_ops had IPMODIFY
		"__x64_sys_read":       true,  // direct call into a module, not a BPF trampoline
	}
	for _, h := range hooks {
		rec := core.NewRecorder(slog.New(slog.NewTextHandler(io.Discard, nil)))
		if got := classify(rec, h, nil); got != want[h.Function] {
			t.Errorf("%s: suspicious=%v, want %v", h.Function, got, want[h.Function])
		}
	}

	// Per-function livepatch: exempts tcp4_seq_show only when tcp4_seq_show itself is patched.
	rec := core.NewRecorder(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if classify(rec, hooks[6], map[string]bool{"tcp4_seq_show": true}) {
		t.Error("IPMODIFY on a live-patched function should only be observed")
	}
	if !classify(rec, hooks[6], map[string]bool{"unrelated_fn": true}) {
		t.Error("IPMODIFY on an unpatched function must stay suspicious even when livepatch is active elsewhere")
	}

	// Canary collision: refcnt > 1 or IPMODIFY on canary target must not be skipped.
	if !isSoleCanary(hooks[0]) {
		t.Error("clean canary should be sole canary")
	}
	if isSoleCanary(hooks[6]) {
		t.Error("co-hooked function with refcnt=2 and IPMODIFY treated as sole canary")
	}
	if !isSoleCanary(hooks[7]) {
		t.Error("pre-6.0 BPF trampoline canary (RID via direct_ops) should be sole canary")
	}
	if isSoleCanary(hooks[8]) {
		t.Error("IPMODIFY direct call into a module treated as sole canary")
	}
}

func TestLivepatchedFunctions(t *testing.T) {
	dir := t.TempDir()
	mk := func(p, content string) {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("patch_a/enabled", "1\n")
	mk("patch_a/vmlinux/cmdline_proc_show,1/patched", "1\n")
	mk("patch_disabled/enabled", "0\n")
	mk("patch_disabled/vmlinux/tcp4_seq_show,0/patched", "0\n")

	got := livepatchedFunctions(dir)
	if !got["cmdline_proc_show"] || got["tcp4_seq_show"] {
		t.Errorf("livepatchedFunctions = %v", got)
	}
}

func TestIsSyscall(t *testing.T) {
	for fn, want := range map[string]bool{
		"__x64_sys_getdents64": true, "__arm64_sys_kill": true, "x64_sys_call": true,
		"do_sys_openat2": false, "tcp4_seq_show": false, "filldir64": false,
	} {
		if isSyscall(fn) != want {
			t.Errorf("isSyscall(%q) != %v", fn, want)
		}
	}
}
