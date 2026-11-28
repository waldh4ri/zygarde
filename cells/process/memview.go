// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package process

import (
	"fmt"
	"os"
	"strconv"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/kmem"
	"github.com/waldh4ri/zygarde/internal/ktask"
)

// The kernel memory view (internal/ktask) replaces the BPF task iterator on
// kernels without one (before Linux 5.8). ZYGARDE_TASK_VIEW=memory forces it
// on newer kernels, to compare both views.
const taskViewEnv = "ZYGARDE_TASK_VIEW"

func useMemoryView(env *core.Env) bool {
	return os.Getenv(taskViewEnv) == "memory" || !core.HasBTFType(env.BTF, "bpf_iter__task")
}

// memViewSupported says whether the memory view can run: it needs BTF (for
// the offsets) and the initial PID namespace (it reads init-namespace IDs,
// which /proc then shows). It finds init_task from its own task, so it needs
// no kernel symbols.
func memViewSupported(env *core.Env) error {
	if err := env.RequireBTF(); err != nil {
		return err
	}
	if _, err := ktask.NewLayout(env.BTF); err != nil {
		return core.Skip("the kernel's BTF lacks task fields the memory view needs: %v", err)
	}
	if init, err := bpfutil.InInitPIDNS(); err != nil || !init {
		return core.Skip("no BPF task iterator (Linux 5.8+), and the kernel memory view needs the initial PID namespace")
	}
	return nil
}

// memView reads task snapshots from kernel memory.
type memView struct {
	mem      *kmem.Reader
	layout   ktask.Layout
	initTask uint64
}

func openMemView(env *core.Env, rec *core.Recorder) (*memView, error) {
	layout, err := ktask.NewLayout(env.BTF)
	if err != nil {
		return nil, err
	}
	mem, err := kmem.Open(env)
	if err != nil {
		return nil, err
	}
	if id := mem.ProgramID(); id != 0 {
		rec.Footprint("bpf_prog_id", strconv.FormatUint(uint64(id), 10))
	}
	// init_task is the root of zygarde's own real_parent chain. That needs
	// no /proc/kallsyms data symbols (CONFIG_KALLSYMS_ALL), and where
	// kallsyms does list init_task the two must agree.
	self, err := mem.CurrentTask()
	if err == nil {
		var initTask uint64
		if initTask, err = ktask.FindInitTask(mem, layout, self); err == nil {
			checkInitTaskSymbol(env, rec, initTask)
			return &memView{mem: mem, layout: layout, initTask: initTask}, nil
		}
	}
	mem.Close()
	return nil, fmt.Errorf("finding init_task: %w", err)
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

func (v *memView) Close() { v.mem.Close() }

// snapshot reads the kernel's tasks and returns them as the iterator would
// (init-namespace IDs, which are zygarde's), with the processes found on
// only one of the two structures walked.
func (v *memView) snapshot() (snapshot, error) {
	view, err := ktask.Snapshot(v.mem, v.layout, v.initTask)
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
