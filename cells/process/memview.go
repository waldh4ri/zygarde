// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package process

import (
	"fmt"
	"strconv"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/ktask"
)

// The kernel memory view (internal/ktask) replaces the BPF task iterator on
// kernels without one (before Linux 5.8); ktask.ForceEnv forces it.
func useMemoryView(env *core.Env) bool { return ktask.Use(env, "bpf_iter__task") }

func memViewSupported(env *core.Env) error {
	return ktask.Supported(env, "BPF task iterator (Linux 5.8+)")
}

// memView reads task snapshots from kernel memory.
type memView struct{ src *ktask.Source }

func openMemView(env *core.Env, rec *core.Recorder) (*memView, error) {
	src, err := ktask.Open(env, rec)
	if err != nil {
		return nil, err
	}
	// Where kallsyms lists init_task, it must be the root ktask found.
	checkInitTaskSymbol(env, rec, src.InitTask)
	return &memView{src: src}, nil
}

// checkInitTaskSymbol compares the root of the process tree with the address
// /proc/kallsyms gives for init_task, when it gives one.
func checkInitTaskSymbol(env *core.Env, rec *core.Recorder, root uint64) {
	ks, err := env.Kallsyms()
	if err != nil {
		return
	}
	sym, ok := ks.Addr("init_task")
	if !ok || sym == root {
		return
	}
	rec.Suspicious(core.Finding{
		Description: fmt.Sprintf("/proc/kallsyms places init_task at %#x, but the root of the process tree is at %#x", sym, root),
		Details:     map[string]string{"kallsyms_init_task": fmt.Sprintf("%#x", sym), "tree_root": fmt.Sprintf("%#x", root)},
		Why: "init_task is the root of every process's chain of parents, and /proc/kallsyms gives its address. " +
			"A different address means /proc/kallsyms is being rewritten, which rootkits do to mislead scanners.",
		Benign: "None expected.",
	})
}

func (v *memView) Close() { v.src.Close() }

// snapshot reads the kernel's tasks and returns them as the iterator would
// (init-namespace IDs, which are zygarde's), with the processes found on
// only one of the two structures walked.
func (v *memView) snapshot() (snapshot, error) {
	view, err := v.src.Snapshot()
	if err != nil {
		return snapshot{}, err
	}
	return fromMemory(view), nil
}

func fromMemory(view *ktask.View) snapshot {
	s := snapshot{
		procs:     map[uint32]processTaskInfo{},
		nsThreads: map[uint32]processTaskInfo{},
		threads:   map[uint32]bool{},
		listOnly:  map[uint32]processTaskInfo{},
		treeOnly:  map[uint32]processTaskInfo{},
	}
	for _, t := range view.Tasks {
		if t.PID == 0 {
			continue
		}
		var start uint64
		if leader := view.Tasks[t.Leader]; leader != nil {
			start = leader.StartBoottime
		}
		info := processTaskInfo{
			Tgid: t.TGID, Pid: t.PID, Ppid: t.PPID, State: t.State,
			GlobalTgid: t.TGID, GlobalPid: t.PID, Flags: t.Flags,
			Uid: t.UID, Euid: t.EUID, Gid: t.GID,
			StartBoottime: t.StartBoottime, StartTime: start,
			TracerPid: t.TracerPID, TracerTgid: t.TracerTGID,
		}
		if t.HasMM {
			info.HasMm = 1
		}
		if t.Ptraced {
			info.Ptraced = 1
		}
		for i, c := range t.Comm {
			info.Comm[i] = int8(c)
		}
		s.threads[t.PID] = true
		s.nsThreads[t.PID] = info
		if _, seen := s.procs[t.TGID]; !seen || t.PID == t.TGID {
			s.procs[t.TGID] = info
		}
		if t.Addr == t.Leader {
			switch {
			case view.List[t.Addr] && !view.Tree[t.Addr]:
				s.listOnly[t.TGID] = info
			case view.Tree[t.Addr] && !view.List[t.Addr]:
				s.treeOnly[t.TGID] = info
			}
		}
	}
	return s
}

// checkUnlinked reports processes found on only one of the two structures
// in both snapshots, with the same start time (so not a PID reuse).
func checkUnlinked(rec *core.Recorder, before, after snapshot) {
	report := func(b, a map[uint32]processTaskInfo, onList bool) {
		for tgid, t := range b {
			if x, ok := a[tgid]; !ok || x.StartTime != t.StartTime {
				continue
			}
			comm := bpfutil.Int8String(t.Comm[:])
			d := map[string]string{
				"pid":  strconv.Itoa(int(tgid)),
				"comm": comm,
				"ppid": strconv.Itoa(int(t.Ppid)),
				"euid": strconv.Itoa(int(t.Euid)),
			}
			f := core.Finding{Details: d, Benign: "None expected: the process was in the same place in two snapshots."}
			if onList {
				f.Description = fmt.Sprintf("Process %d (%s) is on the kernel's task list but not in its parent's children", tgid, comm)
				f.Why = "Every process is linked both on the global task list (init_task.tasks) and in its parent's " +
					"list of children. This one was unlinked from the process tree, which hides it from tools walking it."
			} else {
				f.Description = fmt.Sprintf("Process %d (%s) is in the process tree but unlinked from the kernel's task list", tgid, comm)
				f.Why = "Every process is linked both on the global task list (init_task.tasks) and in its parent's " +
					"list of children. Removing it from the task list hides it from everything that walks that list."
			}
			rec.Suspicious(f)
		}
	}
	report(before.listOnly, after.listOnly, true)
	report(before.treeOnly, after.treeOnly, false)
}
