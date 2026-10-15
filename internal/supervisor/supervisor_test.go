package supervisor

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/waldh4ri/zygarde/internal/core"
)

// testModeEnv makes the re-executed test binary act as a misbehaving worker.
const testModeEnv = "ZYGARDE_TEST_WORKER"

func TestMain(m *testing.M) {
	if mode := os.Getenv(testModeEnv); mode != "" && IsWorker() {
		fakeWorker(mode)
	}
	os.Exit(m.Run())
}

func fakeWorker(mode string) {
	out := os.NewFile(workerFD, "events")
	io.WriteString(out, `{"type":"start","cell":"fake"}`+"\n")
	switch mode {
	case "ok":
		io.WriteString(out, `{"type":"result","cell":"fake","result":{"cell":"fake","name":"Fake","status":0}}`+"\n")
		io.WriteString(out, `{"type":"done"}`+"\n")
		os.Exit(0)
	case "longline":
		// A result line over the protocol limit, then stay alive.
		line := `{"type":"result","x":"` + strings.Repeat("a", maxLine+1024) + `"}` + "\n"
		io.WriteString(out, line)
		time.Sleep(time.Hour)
	case "ignoreterm":
		signal.Ignore(syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
		time.Sleep(time.Hour)
	}
	os.Exit(3)
}

type fakeCell struct{}

func (fakeCell) ID() string                                           { return "fake" }
func (fakeCell) Name() string                                         { return "Fake" }
func (fakeCell) Description() string                                  { return "" }
func (fakeCell) Timeout() time.Duration                               { return time.Minute }
func (fakeCell) Supported(*core.Env) error                            { return nil }
func (fakeCell) Run(context.Context, *core.Env, *core.Recorder) error { return nil }

func run(t *testing.T, ctx context.Context, mode string) (*core.Result, []core.Result, time.Duration) {
	t.Helper()
	t.Setenv(testModeEnv, mode)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	var got []core.Result
	start := time.Now()
	r := runWorker(ctx, []core.Cell{fakeCell{}}, []string{"-test.run=^$"}, log,
		map[string]core.Cell{"fake": fakeCell{}}, Callbacks{}, func(r core.Result) { got = append(got, r) })
	return r, got, time.Since(start)
}

func TestRunWorkerOK(t *testing.T) {
	r, got, _ := run(t, context.Background(), "ok")
	if r != nil || len(got) != 1 || got[0].Cell != "fake" {
		t.Fatalf("runWorker = %+v, recorded %+v", r, got)
	}
}

// A line over the protocol limit must not deadlock parent and worker.
func TestRunWorkerLongLine(t *testing.T) {
	r, _, took := run(t, context.Background(), "longline")
	if r == nil || r.Status != core.StatusError || !strings.Contains(r.Error, "unreadable result") {
		t.Fatalf("runWorker = %+v", r)
	}
	if took > 20*time.Second {
		t.Fatalf("took %v", took)
	}
}

// An interrupted worker that ignores SIGTERM is killed after the grace period.
func TestRunWorkerInterrupt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(500*time.Millisecond, cancel)
	r, _, took := run(t, ctx, "ignoreterm")
	if r == nil || r.Error != "interrupted" {
		t.Fatalf("runWorker = %+v", r)
	}
	if took > termGrace+reapTimeout+5*time.Second {
		t.Fatalf("took %v", took)
	}
}

func TestDeathResultOOM(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	cmd.Process.Kill()
	err := cmd.Wait()
	if r := deathResult(fakeCell{}, err, time.Second, true); r.Status != core.StatusError {
		t.Errorf("SIGKILL during an OOM kill: status %v, want ERROR", r.StatusText)
	}
	if r := deathResult(fakeCell{}, err, time.Second, false); r.Status != core.StatusSuspicious {
		t.Errorf("SIGKILL without OOM kill: status %v, want SUSPICIOUS", r.StatusText)
	}
}

func TestCounter(t *testing.T) {
	if n := counter("oom 1\noom_kill 42\noom_group_kill 3\n", "oom_kill"); n != 42 {
		t.Errorf("counter = %d", n)
	}
}
