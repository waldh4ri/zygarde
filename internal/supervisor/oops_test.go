package supervisor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/kmsg"
)

func withKmsg(t *testing.T, recs []kmsg.Record, err error) {
	t.Helper()
	old := readKmsg
	readKmsg = func() ([]kmsg.Record, error) { return recs, err }
	t.Cleanup(func() { readKmsg = old })
}

var oopsRecs = []kmsg.Record{
	{Seq: 10, Msg: "usb 1-1: new device"},
	{Seq: 11, TimeUS: 5_000_000, Msg: "general protection fault, probably for non-canonical address 0x7fffffff80000000: 0000 [#1] SMP PTI"},
	{Seq: 12, Msg: "CPU: 1 PID: 1038 Comm: exe Tainted: G D OE 5.10.0-46-amd64 #1 Debian 5.10.262-1"},
	{Seq: 13, Msg: "RIP: 0010:sysfs_kf_bin_read+0x57/0x70"},
	{Seq: 14, Msg: "Call Trace:"},
	{Seq: 15, Msg: " kernfs_fop_read_iter+0xa3/0x1b0"},
}

func hung() *core.Result {
	r := &core.Result{Cell: "kernel_pointers", Name: "Function Pointer Integrity", Error: "did not finish within 40s; the worker was stopped"}
	r.SetStatus(core.StatusError)
	return r
}

func TestAttachOopsUpgradesFailedCell(t *testing.T) {
	withKmsg(t, oopsRecs, nil)
	r := attachOops(hung(), 10, true, []string{"/sys/module/diamorphine/sections/.bss"})
	if r.Status != core.StatusSuspicious || r.Error != "" || len(r.Findings) != 1 {
		t.Fatalf("result = %+v", r)
	}
	f := r.Findings[0]
	if f.Details["files_being_read"] != "/sys/module/diamorphine/sections/.bss" || f.Details["faulting_task_is_scanner"] != "true" ||
		!strings.Contains(f.Description, "sysfs_kf_bin_read") {
		t.Errorf("finding = %+v", f)
	}
	if len(r.Limitations) != 1 || !strings.Contains(r.Limitations[0], "did not complete") {
		t.Errorf("limitations = %v", r.Limitations)
	}
}

func TestAttachOopsLeavesOtherFailuresAlone(t *testing.T) {
	// An oops from before the worker started is not attributed to it.
	withKmsg(t, oopsRecs, nil)
	if r := attachOops(hung(), 15, true, nil); r.Status != core.StatusError || len(r.Findings) != 0 {
		t.Errorf("old oops attributed: %+v", r)
	}
	// No mark (the log was unreadable at start), or an unreadable log now.
	if r := attachOops(hung(), 0, false, nil); r.Status != core.StatusError {
		t.Error("attributed without a mark")
	}
	withKmsg(t, nil, os.ErrPermission)
	if r := attachOops(hung(), 0, true, nil); r.Status != core.StatusError {
		t.Error("attributed from an unreadable log")
	}
	if attachOops(nil, 0, true, nil) != nil {
		t.Error("nil result")
	}
}

func TestSuspectFiles(t *testing.T) {
	proc := t.TempDir()
	pid := filepath.Join(proc, "321")
	for _, d := range []string{"task/321", "task/330", "fd"} {
		if err := os.MkdirAll(filepath.Join(pid, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Thread 330 is stuck in read(fd 9, ...); thread 321 is running.
	write := func(p, s string) {
		if err := os.WriteFile(filepath.Join(pid, p), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("task/330/syscall", "0 0x9 0xc002023a00 0x200 0x0 0x0 0x0 0x7ffc 0x403f6e\n")
	write("task/321/syscall", "running\n")
	link := func(n, target string) {
		if err := os.Symlink(target, filepath.Join(pid, "fd", n)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	link("3", "pipe:[1234]")
	link("9", "/sys/module/diamorphine/sections/.bss")
	link("10", "/proc/net/tcp")
	link("11", "/etc/passwd") // not kernel-backed

	got := suspectFiles(proc, 321)
	want := "/sys/module/diamorphine/sections/.bss,/proc/net/tcp" // the blocked one first
	if strings.Join(got, ",") != want {
		t.Errorf("suspectFiles = %v, want %s", got, want)
	}
	if len(suspectFiles(proc, 999)) != 0 {
		t.Error("missing process")
	}
}
