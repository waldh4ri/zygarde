package taint

import (
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/kmsg"
)

func newRec() *core.Recorder {
	return core.NewRecorder(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func fakeLog(msgs ...string) func() ([]kmsg.Record, error) {
	return func() ([]kmsg.Record, error) {
		var out []kmsg.Record
		for i, m := range msgs {
			out = append(out, kmsg.Record{Seq: uint64(i + 1), TimeUS: int64(i+1) * 1_000_000, Msg: m})
		}
		return out, nil
	}
}

func TestCheckOopsesReportsLoggedOops(t *testing.T) {
	c := &Cell{kmsg: fakeLog(
		"general protection fault, probably for non-canonical address 0x7fffffff80000000: 0000 [#1] SMP PTI",
		"CPU: 0 PID: 1029 Comm: exe Tainted: G OE 5.10.0-46-amd64 #1 Debian 5.10.262-1",
		"RIP: 0010:sysfs_kf_bin_read+0x57/0x70",
		"Call Trace:",
		" kernfs_fop_read_iter+0xa3/0x1b0",
	)}
	r := newRec()
	if n := c.checkOopses(r, 1<<taintDie); n != 1 {
		t.Fatalf("n = %d, want 1", n)
	}
	f := r.Findings()[0]
	if !strings.Contains(f.Description, "sysfs_kf_bin_read") || f.Details["faulting_task"] != "exe (1029)" ||
		f.Details["call_trace"] != "kernfs_fop_read_iter" {
		t.Errorf("finding = %+v", f)
	}
}

func TestCheckOopsesTaintWithoutLog(t *testing.T) {
	c := &Cell{kmsg: fakeLog("usb 1-1: new high-speed USB device")}
	r := newRec()
	if n := c.checkOopses(r, 1<<taintDie); n != 1 || !strings.Contains(r.Findings()[0].Description, "no longer holds") {
		t.Errorf("n = %d, findings = %+v", n, r.Findings())
	}
}

func TestCheckOopsesQuietHost(t *testing.T) {
	r := newRec()
	if n := (&Cell{kmsg: fakeLog("usb 1-1: new device")}).checkOopses(r, 0); n != 0 || len(r.Findings()) != 0 {
		t.Errorf("clean host reported %d findings", n)
	}
	// An unreadable log is only a limit, and only when taint 'D' is set.
	unreadable := &Cell{kmsg: func() ([]kmsg.Record, error) { return nil, errors.New("permission denied") }}
	r = newRec()
	if n := unreadable.checkOopses(r, 0); n != 0 || len(r.Findings()) != 0 {
		t.Errorf("unreadable log without taint: %d", n)
	}
	if n := unreadable.checkOopses(r, 1<<taintDie); n != 0 || len(r.Findings()) != 0 {
		t.Errorf("unreadable log with taint reported a finding: %d", n)
	}
}
