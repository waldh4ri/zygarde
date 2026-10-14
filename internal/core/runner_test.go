package core

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/kernel"
)

type fakeCell struct {
	supported error
	run       func(rec *Recorder) error
}

func (*fakeCell) ID() string             { return "fake" }
func (*fakeCell) Name() string           { return "Fake" }
func (*fakeCell) Description() string    { return "fake cell" }
func (*fakeCell) Timeout() time.Duration { return time.Second }
func (c *fakeCell) Supported(*Env) error { return c.supported }
func (c *fakeCell) Run(_ context.Context, _ *Env, rec *Recorder) error {
	return c.run(rec)
}

func testEnv(euid, seccomp int) *Env {
	return &Env{
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		EUID:   euid,
		Status: kernel.ProcStatus{Seccomp: seccomp},
	}
}

func TestRunCell(t *testing.T) {
	root := testEnv(0, 0)
	for _, tc := range []struct {
		name     string
		env      *Env
		cell     *fakeCell
		want     Status
		findings int
	}{
		{"ok", root, &fakeCell{run: func(*Recorder) error { return nil }}, StatusOK, 0},
		{"skip from Supported", root, &fakeCell{supported: Skip("nope")}, StatusSkipped, 0},
		{"skip from Run", root, &fakeCell{run: func(*Recorder) error { return Skip("nope") }}, StatusSkipped, 0},
		{"not supported by kernel", root, &fakeCell{run: func(*Recorder) error { return ebpf.ErrNotSupported }}, StatusSkipped, 0},
		{"plain error", root, &fakeCell{run: func(*Recorder) error { return errors.New("boom") }}, StatusError, 0},
		{"finding", root, &fakeCell{run: func(rec *Recorder) error {
			rec.Suspicious("bad", nil)
			return nil
		}}, StatusSuspicious, 1},
		{"canary missing", root, &fakeCell{run: func(rec *Recorder) error {
			rec.Canary("x", "view A", true)
			rec.Canary("x", "view B", false)
			return nil
		}}, StatusSuspicious, 1},
		{"finding survives later error", root, &fakeCell{run: func(rec *Recorder) error {
			rec.Suspicious("bad", nil)
			return errors.New("boom")
		}}, StatusSuspicious, 1},
		{"bpf denied while expected to work", root, &fakeCell{run: func(*Recorder) error {
			return WrapBPF("load", unix.EPERM)
		}}, StatusSuspicious, 1},
		{"bpf denied under seccomp", testEnv(0, 2), &fakeCell{run: func(*Recorder) error {
			return WrapBPF("load", unix.EPERM)
		}}, StatusError, 0},
		{"bpf denied unprivileged", testEnv(1000, 0), &fakeCell{run: func(*Recorder) error {
			return WrapBPF("load", unix.EPERM)
		}}, StatusError, 0},
		{"bpf denied with memlock stuck", func() *Env {
			e := testEnv(0, 0)
			e.MemlockErr = errors.New("setrlimit: operation not permitted")
			return e
		}(), &fakeCell{run: func(*Recorder) error {
			return WrapBPF("load", unix.EPERM)
		}}, StatusError, 0},
		{"EPERM outside bpf()", root, &fakeCell{run: func(*Recorder) error { return unix.EPERM }}, StatusError, 0},
		{"panic", root, &fakeCell{run: func(*Recorder) error { panic("oops") }}, StatusError, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := RunCell(context.Background(), tc.env, tc.cell)
			if r.Status != tc.want || r.StatusText != tc.want.String() {
				t.Errorf("status = %v (%q), want %v", r.Status, r.StatusText, tc.want)
			}
			if len(r.Findings) != tc.findings {
				t.Errorf("findings = %d, want %d: %+v", len(r.Findings), tc.findings, r.Findings)
			}
		})
	}
}

func TestExitCode(t *testing.T) {
	res := func(ss ...Status) []Result {
		var out []Result
		for _, s := range ss {
			out = append(out, Result{Status: s})
		}
		return out
	}
	for _, tc := range []struct {
		results []Result
		want    int
	}{
		{res(StatusOK, StatusSkipped), 0},
		{res(StatusOK, StatusError), 1},
		{res(StatusError, StatusSuspicious, StatusOK), 2},
	} {
		if got := ExitCode(tc.results); got != tc.want {
			t.Errorf("ExitCode(%v) = %d, want %d", tc.results, got, tc.want)
		}
	}
}
