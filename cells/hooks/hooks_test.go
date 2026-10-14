package hooks

import (
	"io"
	"log/slog"
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
`

func TestParse(t *testing.T) {
	hooks, err := parseEnabledFunctions(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(hooks) != 7 {
		t.Fatalf("parsed %d hooks, want 7: %+v", len(hooks), hooks)
	}
	h := hooks[0]
	if h.Function != "__x64_sys_getppid" || !h.Flags['D'] || len(h.Direct) != 1 {
		t.Errorf("BPF trampoline parsed wrong: %+v", h)
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
	}
	for _, h := range hooks {
		rec := core.NewRecorder(slog.New(slog.NewTextHandler(io.Discard, nil)))
		if got := classify(rec, h, false); got != want[h.Function] {
			t.Errorf("%s: suspicious=%v, want %v", h.Function, got, want[h.Function])
		}
	}

	rec := core.NewRecorder(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if classify(rec, hooks[6], true) {
		t.Error("unattributed IPMODIFY with livepatch active should only be observed")
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
