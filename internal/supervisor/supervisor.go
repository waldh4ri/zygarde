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
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/canary"
	"github.com/waldh4ri/zygarde/internal/core"
)

const (
	// RoleWorker is the canary.RoleEnv value of a worker process.
	RoleWorker = "worker"
	// CellsEnv lists the Cell IDs a worker must run, comma-separated.
	CellsEnv = "ZYGARDE_CELLS"

	// grace is added to a Cell's own timeout before the worker is killed.
	grace = 10 * time.Second
	// workerFD is the worker's end of the event pipe (first ExtraFiles entry).
	workerFD = 3
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
	cmd := exec.Command("/proc/self/exe", args...)
	cmd.Env = append(os.Environ(), canary.RoleEnv+"="+RoleWorker, CellsEnv+"="+strings.Join(ids, ","))
	cmd.Stdout = os.Stderr // the worker must not write to our stdout (JSON mode)
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{pw}
	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return workerFailure(todo[0], fmt.Errorf("starting worker: %w", err), 0)
	}
	pw.Close()
	defer pr.Close()
	log.Debug("worker started", "pid", cmd.Process.Pid, "cells", ids)

	events := make(chan event)
	go func() {
		defer close(events)
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
		for sc.Scan() {
			var ev event
			if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
				log.Error("bad message from worker", "err", err)
				continue
			}
			events <- ev
		}
	}()

	var (
		current  core.Cell
		started  time.Time
		timer    = time.NewTimer(time.Hour)
		timedOut bool
		done     bool
	)
	timer.Stop()
	defer timer.Stop()

loop:
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				break loop
			}
			switch ev.Type {
			case "start":
				current = byID[ev.Cell]
				if current == nil {
					log.Error("worker started an unknown cell", "cell", ev.Cell)
					continue
				}
				started = time.Now()
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
		case <-timer.C:
			timedOut = true
			log.Debug("cell exceeded its timeout, killing worker", "cell", current.ID())
			_ = cmd.Process.Kill()
		case <-ctx.Done():
			_ = cmd.Process.Kill()
		}
	}

	waitErr := cmd.Wait()
	canary.RemoveFiles(canary.FileDir, cmd.Process.Pid)
	if done && waitErr == nil {
		return nil
	}
	if current == nil {
		if waitErr != nil {
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
	case ctx.Err() != nil:
		return workerFailure(current, errors.New("interrupted"), elapsed)
	default:
		return deathResult(current, waitErr, elapsed)
	}
}

// deathResult describes a worker that died while running a Cell.
func deathResult(c core.Cell, waitErr error, elapsed time.Duration) *core.Result {
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			sig := unix.SignalName(ws.Signal())
			r := &core.Result{Cell: c.ID(), Name: c.Name(), DurationSeconds: elapsed.Seconds()}
			r.SetStatus(core.StatusSuspicious)
			r.Error = fmt.Sprintf("worker killed by %s", sig)
			r.Message = "the scanner was killed while running this cell"
			r.Findings = []core.Finding{{
				Description: fmt.Sprintf("The scanner's worker process was killed by %s while running this Cell", sig),
				Details:     map[string]string{"signal": sig},
				Why: "Zygarde did not send this signal. Something on the system terminated the scanner in the middle " +
					"of this check, which is how malware avoids being inspected.",
				Benign: "The kernel's OOM killer (look for \"Out of memory\" in dmesg), or an administrator or " +
					"security tool killing the process.",
			}}
			return r
		}
	}
	return workerFailure(c, fmt.Errorf("worker exited unexpectedly: %v", waitErr), elapsed)
}

func workerFailure(c core.Cell, err error, elapsed time.Duration) *core.Result {
	r := &core.Result{Cell: c.ID(), Name: c.Name(), Error: err.Error(), DurationSeconds: elapsed.Seconds()}
	r.SetStatus(core.StatusError)
	return r
}

// Worker is the body of a worker process: run the Cells named in CellsEnv
// and stream events to the parent.
func Worker(ctx context.Context, all []core.Cell, env *core.Env) error {
	out := os.NewFile(workerFD, "events")
	if out == nil {
		return errors.New("event pipe missing")
	}
	defer out.Close()
	enc := json.NewEncoder(out)

	byID := make(map[string]core.Cell, len(all))
	for _, c := range all {
		byID[c.ID()] = c
	}
	for _, id := range strings.Split(os.Getenv(CellsEnv), ",") {
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
