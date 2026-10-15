// Package supervisor runs Cells in a child worker process and watches it.
//
// If something on the system kills or freezes the scanner, the parent still
// produces a report and says so, instead of dying silently with it. The
// parent then starts a new worker for the Cells that haven't run yet.
package supervisor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/canary"
	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fsutil"
	"github.com/waldh4ri/zygarde/internal/kernel"
)

const (
	// RoleWorker is the canary.RoleEnv value of a worker process.
	RoleWorker = "worker"
	// CellsEnv lists the Cell IDs a worker must run, comma-separated.
	CellsEnv = "ZYGARDE_CELLS"

	// grace is added to a Cell's own timeout before the worker is killed.
	grace = 10 * time.Second
	// termGrace is how long an interrupted worker gets to clean up (detach
	// probes, remove canaries) after SIGTERM, before SIGKILL.
	termGrace = 3 * time.Second
	// reapTimeout is how long a killed worker may take to exit. One stuck
	// in uninterruptible I/O (a dead NFS server) is abandoned after that.
	reapTimeout = 5 * time.Second
	// workerFD is the worker's end of the event pipe (first ExtraFiles entry).
	workerFD = 3
	// maxLine bounds one protocol line. Recorder caps observations, so
	// results stay far below it.
	maxLine = 16 * 1024 * 1024
)

// event is one line of the worker -> parent protocol.
type event struct {
	Type   string       `json:"type"` // "start", "result" or "done"
	Cell   string       `json:"cell,omitempty"`
	Result *core.Result `json:"result,omitempty"`
}

// Callbacks let the caller stream progress.
type Callbacks struct {
	Start  func(c core.Cell)
	Result func(r core.Result)
}

// Supervise runs cells in worker processes and returns their results in order.
// args are passed to each worker so it sees the same flags as the parent.
func Supervise(ctx context.Context, cells []core.Cell, args []string, log *slog.Logger, cb Callbacks) []core.Result {
	byID := make(map[string]core.Cell, len(cells))
	for _, c := range cells {
		byID[c.ID()] = c
	}
	results := make(map[string]core.Result, len(cells))

	pending := func() []core.Cell {
		var out []core.Cell
		for _, c := range cells {
			if _, done := results[c.ID()]; !done {
				out = append(out, c)
			}
		}
		return out
	}
	record := func(r core.Result) {
		results[r.Cell] = r
		if cb.Result != nil {
			cb.Result(r)
		}
	}

	for attempt := 0; attempt <= len(cells); attempt++ {
		todo := pending()
		if len(todo) == 0 || ctx.Err() != nil {
			break
		}
		failed := runWorker(ctx, todo, args, log, byID, cb, record)
		if failed == nil {
			continue
		}
		record(*failed)
	}

	out := make([]core.Result, 0, len(cells))
	for _, c := range cells {
		r, ok := results[c.ID()]
		if !ok {
			r = core.Result{Cell: c.ID(), Name: c.Name(), Error: "not run: the scan was interrupted"}
			r.SetStatus(core.StatusError)
		}
		out = append(out, r)
	}
	return out
}

// startWorker starts a worker in a mount namespace of its own, so that
// anything it mounts (tracefs) can never leak to the host, even if it is
// killed. Where that is not allowed (a container without CAP_SYS_ADMIN),
// it falls back to a plain child.
//
// Pdeathsig kills the worker if the parent dies. Linux sends it when the OS
// thread that forked the child exits, not the process: the caller must keep
// the current goroutine locked to its thread while the worker runs.
func startWorker(args, env []string, pipe *os.File, log *slog.Logger) (*exec.Cmd, error) {
	newCmd := func(unshare uintptr) *exec.Cmd {
		cmd := exec.Command("/proc/self/exe", args...)
		cmd.Env = env
		cmd.Stdout = os.Stderr // the worker must not write to our stdout (JSON mode)
		cmd.Stderr = os.Stderr
		cmd.ExtraFiles = []*os.File{pipe}
		// Go also makes / recursively private in the child, so mounts
		// don't propagate back to the host.
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Unshareflags: unshare}
		return cmd
	}
	cmd := newCmd(unix.CLONE_NEWNS)
	err := cmd.Start()
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EINVAL) {
		log.Debug("worker can't have its own mount namespace", "err", err)
		cmd = newCmd(0)
		err = cmd.Start()
	}
	return cmd, err
}

// runWorker runs one worker until it finishes or dies. If it dies or hangs
// in the middle of a Cell, it returns a Result describing that for the Cell.
func runWorker(ctx context.Context, todo []core.Cell, args []string, log *slog.Logger,
	byID map[string]core.Cell, cb Callbacks, record func(core.Result)) *core.Result {

	ids := make([]string, len(todo))
	for i, c := range todo {
		ids[i] = c.ID()
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		return workerFailure(todo[0], fmt.Errorf("creating pipe: %w", err), 0)
	}
	// Keep this thread alive for the worker's lifetime (see startWorker).
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cmd, err := startWorker(args, canary.ChildEnv(RoleWorker, CellsEnv+"="+strings.Join(ids, ",")), pw, log)
	pw.Close()
	if err != nil {
		pr.Close()
		return workerFailure(todo[0], fmt.Errorf("starting worker: %w", err), 0)
	}
	defer pr.Close()
	pid := cmd.Process.Pid
	log.Debug("worker started", "pid", pid, "cells", ids)

	quit := make(chan struct{})
	defer close(quit)
	events := make(chan event)
	readErr := make(chan error, 1)
	go func() {
		defer close(events)
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 0, 64*1024), maxLine)
		for sc.Scan() {
			var ev event
			if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
				log.Error("bad message from worker", "err", err)
				continue
			}
			select {
			case events <- ev:
			case <-quit:
				return
			}
		}
		if err := sc.Err(); err != nil {
			readErr <- err
			// Keep draining so the worker never blocks writing to us.
			_, _ = io.Copy(io.Discard, pr)
		}
	}()

	var waitErr error
	exited := make(chan struct{})
	go func() {
		waitErr = cmd.Wait()
		close(exited)
	}()

	var (
		current     core.Cell
		started     time.Time
		oomBefore   uint64
		timer       = time.NewTimer(time.Hour)
		timedOut    bool
		interrupted bool
		protoErr    error
		done        bool
		killed      bool
		reaped      bool
		termTimer   <-chan time.Time
		abandon     <-chan time.Time
		ctxDone     = ctx.Done()
	)
	timer.Stop()
	defer timer.Stop()
	kill := func() {
		if !killed {
			killed = true
			_ = cmd.Process.Kill()
			abandon = time.After(reapTimeout)
		}
	}

loop:
	for events != nil || !reaped {
		select {
		case ev, ok := <-events:
			if !ok {
				events = nil
				if !done {
					// EOF without "done": the worker is dying or closed
					// the pipe; make sure it is gone before waiting.
					kill()
				} else if abandon == nil {
					abandon = time.After(reapTimeout)
				}
				continue
			}
			switch ev.Type {
			case "start":
				current = byID[ev.Cell]
				if current == nil {
					log.Error("worker started an unknown cell", "cell", ev.Cell)
					continue
				}
				started = time.Now()
				oomBefore = oomKills()
				timer.Reset(current.Timeout() + grace)
				if cb.Start != nil {
					cb.Start(current)
				}
			case "result":
				timer.Stop()
				if ev.Result != nil {
					record(*ev.Result)
				}
				current = nil
			case "done":
				done = true
			}
		case err := <-readErr:
			protoErr = err
			log.Error("unreadable message from worker, stopping it", "err", err)
			kill()
		case <-timer.C:
			timedOut = true
			if current != nil {
				log.Debug("cell exceeded its timeout, killing worker", "cell", current.ID())
			}
			kill()
		case <-ctxDone:
			// Let the worker's deferred cleanup run, then insist.
			ctxDone = nil
			interrupted = true
			_ = cmd.Process.Signal(syscall.SIGTERM)
			termTimer = time.After(termGrace)
		case <-termTimer:
			termTimer = nil
			kill()
		case <-exited:
			exited = nil
			reaped = true
			if events != nil && abandon == nil {
				// Something else may still hold the pipe open: don't wait on it forever.
				abandon = time.After(reapTimeout)
			}
		case <-abandon:
			abandon = nil
			if !reaped && !killed {
				kill() // finished but did not exit
				continue
			}
			break loop
		}
	}

	if !reaped {
		log.Error("worker could not be stopped; abandoning it", "pid", pid)
		if current == nil {
			return nil
		}
		return workerFailure(current, fmt.Errorf("worker pid %d did not exit %v after SIGKILL "+
			"(likely blocked in uninterruptible I/O, e.g. an unreachable network filesystem); it was abandoned",
			pid, reapTimeout), time.Since(started))
	}
	canary.RemoveFiles(canary.FileDir, pid)
	if done && waitErr == nil {
		return nil
	}
	if current == nil {
		if waitErr != nil && !done {
			log.Error("worker exited between cells", "err", waitErr)
		}
		return nil // the next attempt runs the remaining cells
	}
	elapsed := time.Since(started)
	switch {
	case timedOut:
		r := workerFailure(current, fmt.Errorf("did not finish within %v; the worker was stopped", current.Timeout()+grace), elapsed)
		r.Message = "the cell hung; something may be stalling the scanner"
		return r
	case interrupted:
		return workerFailure(current, errors.New("interrupted"), elapsed)
	case protoErr != nil:
		return workerFailure(current, fmt.Errorf("unreadable result from the worker (%v); the worker was stopped", protoErr), elapsed)
	default:
		return deathResult(current, waitErr, elapsed, oomKills() > oomBefore)
	}
}

// deathResult describes a worker that died while running a Cell. oom is
// true if the kernel's OOM killer killed a process meanwhile.
func deathResult(c core.Cell, waitErr error, elapsed time.Duration, oom bool) *core.Result {
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			sig := unix.SignalName(ws.Signal())
			if oom && ws.Signal() == syscall.SIGKILL {
				r := workerFailure(c, fmt.Errorf("worker killed by %s while the kernel's OOM killer was active", sig), elapsed)
				r.Message = "the scanner ran out of memory while running this cell (see \"Out of memory\" in dmesg)"
				return r
			}
			r := &core.Result{Cell: c.ID(), Name: c.Name(), DurationSeconds: elapsed.Seconds()}
			r.SetStatus(core.StatusSuspicious)
			r.Error = fmt.Sprintf("worker killed by %s", sig)
			r.Message = "the scanner was killed while running this cell"
			r.Findings = []core.Finding{{
				Description: fmt.Sprintf("The scanner's worker process was killed by %s while running this Cell", sig),
				Details:     map[string]string{"signal": sig},
				Why: "Zygarde did not send this signal. Something on the system terminated the scanner in the middle " +
					"of this check, which is how malware avoids being inspected.",
				Benign: "An administrator or security tool killing the process. The kernel's OOM killer is ruled " +
					"out: its kill counter did not change while this Cell ran.",
			}}
			return r
		}
	}
	return workerFailure(c, fmt.Errorf("worker exited unexpectedly: %v", waitErr), elapsed)
}

// oomKills returns how many processes the kernel's OOM killer has killed:
// the system-wide counter in /proc/vmstat (Linux 4.13+) plus that of
// zygarde's own memory cgroup (cgroup v2), which a memory limit on the
// cgroup triggers. It returns 0 when neither is available.
func oomKills() uint64 {
	var n uint64
	if data, err := os.ReadFile("/proc/vmstat"); err == nil {
		n += counter(string(data), "oom_kill")
	}
	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if path, ok := strings.CutPrefix(line, "0::"); ok {
				if ev, err := fsutil.ReadFile("/sys/fs/cgroup"+path+"/memory.events", 1<<16); err == nil {
					n += counter(string(ev), "oom_kill")
				}
			}
		}
	}
	return n
}

// counter returns the value of a "name value" line.
func counter(text, name string) uint64 {
	for _, line := range strings.Split(text, "\n") {
		if k, v, ok := strings.Cut(line, " "); ok && k == name {
			n, _ := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			return n
		}
	}
	return 0
}

func workerFailure(c core.Cell, err error, elapsed time.Duration) *core.Result {
	r := &core.Result{Cell: c.ID(), Name: c.Name(), Error: err.Error(), DurationSeconds: elapsed.Seconds()}
	r.SetStatus(core.StatusError)
	return r
}

// IsWorker reports whether this process was started as a worker: its
// zygarde parent set the role, and fd 3 is the event pipe.
func IsWorker() bool {
	if canary.Role() != RoleWorker {
		return false
	}
	var st unix.Stat_t
	return unix.Fstat(workerFD, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFIFO
}

// Worker is the body of a worker process: run the Cells named in CellsEnv
// and stream events to the parent.
func Worker(ctx context.Context, all []core.Cell, env *core.Env) error {
	// Children (canary processes) must not inherit the pipe, or the parent
	// would wait for them to see EOF.
	unix.CloseOnExec(workerFD)
	out := os.NewFile(workerFD, "events")
	if out == nil {
		return errors.New("event pipe missing")
	}
	defer out.Close()
	enc := json.NewEncoder(out)

	if self, err := os.Readlink("/proc/self/ns/mnt"); err == nil {
		if parent, err := os.Readlink("/proc/" + strconv.Itoa(os.Getppid()) + "/ns/mnt"); err == nil && parent != self {
			kernel.SetPrivateMounts(true)
		}
	}

	byID := make(map[string]core.Cell, len(all))
	for _, c := range all {
		byID[c.ID()] = c
	}
	for _, id := range strings.Split(os.Getenv(CellsEnv), ",") {
		if ctx.Err() != nil {
			break // interrupted: the parent reports the rest as not run
		}
		c, ok := byID[id]
		if !ok {
			continue
		}
		if err := enc.Encode(event{Type: "start", Cell: id}); err != nil {
			return err
		}
		res := core.RunCell(ctx, env, c)
		if err := enc.Encode(event{Type: "result", Cell: id, Result: &res}); err != nil {
			return err
		}
	}
	return enc.Encode(event{Type: "done"})
}
