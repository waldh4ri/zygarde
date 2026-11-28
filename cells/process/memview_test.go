// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package process

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/ktask"
)

func memTask(addr, leader uint64, pid, tgid uint32, comm string, start uint64) *ktask.Task {
	t := &ktask.Task{Addr: addr, Leader: leader, PID: pid, TGID: tgid, StartBoottime: start, HasMM: true}
	copy(t.Comm[:], comm)
	return t
}

func memSnapshot(listOnly, treeOnly bool) snapshot {
	v := &ktask.View{
		List:  map[uint64]bool{0x1000: true, 0x2000: true},
		Tree:  map[uint64]bool{0x1000: true, 0x2000: true},
		Tasks: map[uint64]*ktask.Task{},
	}
	v.Tasks[0x1000] = memTask(0x1000, 0x1000, 1, 1, "systemd", 10)
	v.Tasks[0x2000] = memTask(0x2000, 0x2000, 100, 100, "nginx", 20)
	v.Tasks[0x2100] = memTask(0x2100, 0x2000, 101, 100, "nginx-w", 30)
	v.Tasks[0x3000] = memTask(0x3000, 0x3000, 200, 200, "implant", 40)
	v.Tasks[0x4000] = memTask(0x4000, 0x4000, 300, 300, "odd", 50)
	if treeOnly {
		v.Tree[0x3000] = true // unlinked from init_task.tasks
	} else {
		v.List[0x3000], v.Tree[0x3000] = true, true
	}
	if listOnly {
		v.List[0x4000] = true // missing from the process tree
	} else {
		v.List[0x4000], v.Tree[0x4000] = true, true
	}
	return fromMemory(v)
}

// The memory view converts to the iterator's records: processes by TGID
// (leader preferred), threads by TID, the leader's start as process start.
func TestFromMemory(t *testing.T) {
	s := memSnapshot(false, false)
	if len(s.procs) != 4 || len(s.nsThreads) != 5 || !s.threads[101] {
		t.Fatalf("procs %d, threads %d", len(s.procs), len(s.nsThreads))
	}
	w := s.nsThreads[101]
	if w.Tgid != 100 || w.GlobalPid != 101 || w.StartTime != 20 || w.StartBoottime != 30 || w.HasMm != 1 {
		t.Errorf("thread record = %+v", w)
	}
	if p := s.procs[100]; p.Pid != 100 {
		t.Errorf("process 100 is represented by thread %d, want its leader", p.Pid)
	}
	if len(s.listOnly)+len(s.treeOnly) != 0 {
		t.Errorf("consistent view reports unlinked processes: %v %v", s.listOnly, s.treeOnly)
	}
}

// A process on only one structure in both snapshots is reported; in one
// snapshot only (a race with fork or exit) it is not.
func TestCheckUnlinked(t *testing.T) {
	rec := core.NewRecorder(slog.New(slog.NewTextHandler(io.Discard, nil)))
	checkUnlinked(rec, memSnapshot(true, true), memSnapshot(true, true))
	var got []string
	for _, f := range rec.Findings() {
		got = append(got, f.Description)
	}
	all := strings.Join(got, "\n")
	for _, want := range []string{
		"Process 200 (implant) is in the process tree but unlinked from the kernel's task list",
		"Process 300 (odd) is on the kernel's task list but not in its parent's children",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("findings lack %q:\n%s", want, all)
		}
	}
	if len(got) != 2 {
		t.Errorf("%d findings, want 2:\n%s", len(got), all)
	}

	rec = core.NewRecorder(slog.New(slog.NewTextHandler(io.Discard, nil)))
	checkUnlinked(rec, memSnapshot(true, true), memSnapshot(false, false))
	if n := len(rec.Findings()); n != 0 {
		t.Errorf("seen in one snapshot only: %d findings, want 0", n)
	}
}
