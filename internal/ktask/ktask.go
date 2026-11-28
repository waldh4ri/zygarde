// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

// Package ktask builds the kernel's view of its tasks by reading kernel
// memory directly (internal/kmem) with struct offsets from BTF. It needs no
// BPF iterator, so it works on kernels before Linux 5.8, and it calls no
// kernel enumeration code that a rootkit could hook (getdents, /proc
// readdir, next_tgid, the task iterator's own walk).
//
// Processes are found two independent ways:
//   - the global task list, init_task.tasks, which every process (thread
//     group leader) is on;
//   - the process tree, walked down children/sibling from init_task.
//
// A process present in one and not the other has been unlinked from it.
// Threads come from each process's signal->thread_head.
package ktask

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/btf"

	"github.com/waldh4ri/zygarde/internal/kmem"
)

// Bounds on what one walk visits: far above real systems (pid_max is at
// most 4 Mi, and processes are a fraction of tasks), low enough that a
// corrupted list can't keep a walk going.
const (
	maxProcesses = 1 << 20
	maxThreads   = 1 << 16 // per process
	walkRetries  = 5       // a list changed under the walk: try again
)

// Kernel constants used by callers (include/linux/sched.h, ptrace.h).
const (
	PFExiting = 0x00000004
	PFKthread = 0x00200000
	PTPtraced = 0x00000001
)

// Layout holds the offsets the walk needs, from BTF.
type Layout struct {
	tasks, children, sibling, threadNode   uint64 // task_struct list links
	signal, threadHead                     uint64 // task_struct.signal, signal_struct.thread_head
	pid, tgid, comm, flags, mm, ptrace     uint64
	realParent, parent, cred, start, state uint64
	stateSize, commSize                    uint64
	uid, euid, gid                         uint64 // in struct cred (kuid_t/kgid_t .val)
}

// NewLayout reads the offsets from BTF. It fails when a member is missing,
// so the walk never reads at a guessed offset.
func NewLayout(spec *btf.Spec) (Layout, error) {
	var l Layout
	var errs []error
	get := func(typ, path string, dst *uint64) {
		f, err := kmem.Lookup(spec, typ, path)
		if err != nil {
			errs = append(errs, err)
			return
		}
		*dst = f.Offset
	}
	for _, f := range []struct {
		path string
		dst  *uint64
	}{
		{"tasks", &l.tasks}, {"children", &l.children}, {"sibling", &l.sibling},
		{"thread_node", &l.threadNode}, {"signal", &l.signal},
		{"pid", &l.pid}, {"tgid", &l.tgid}, {"flags", &l.flags}, {"mm", &l.mm},
		{"ptrace", &l.ptrace}, {"real_parent", &l.realParent}, {"parent", &l.parent},
		{"cred", &l.cred},
	} {
		get("task_struct", f.path, f.dst)
	}
	get("signal_struct", "thread_head", &l.threadHead)
	get("cred", "uid.val", &l.uid)
	get("cred", "euid.val", &l.euid)
	get("cred", "gid.val", &l.gid)
	if c, err := kmem.Lookup(spec, "task_struct", "comm"); err == nil {
		l.comm, l.commSize = c.Offset, min(c.Size, 16)
	} else {
		errs = append(errs, err)
	}
	// Linux 5.14 renamed state to __state (and made it 4 bytes).
	if s, err := kmem.Lookup(spec, "task_struct", "__state"); err == nil {
		l.state, l.stateSize = s.Offset, s.Size
	} else if s, err := kmem.Lookup(spec, "task_struct", "state"); err == nil {
		l.state, l.stateSize = s.Offset, s.Size
	} else {
		errs = append(errs, errors.New("struct task_struct: no member __state or state"))
	}
	// Linux 5.5 renamed real_start_time (boot-based) to start_boottime.
	if s, err := kmem.Lookup(spec, "task_struct", "start_boottime"); err == nil {
		l.start = s.Offset
	} else if s, err := kmem.Lookup(spec, "task_struct", "real_start_time"); err == nil {
		l.start = s.Offset
	} else {
		errs = append(errs, errors.New("struct task_struct: no member start_boottime or real_start_time"))
	}
	return l, errors.Join(errs...)
}

// Task is one task as read from kernel memory. IDs are init-namespace ones.
type Task struct {
	Addr          uint64
	Leader        uint64 // address of its thread group leader
	PID, TGID     uint32
	PPID          uint32 // real parent's TGID
	Comm          [16]byte
	Flags         uint32
	HasMM         bool
	State         uint32
	StartBoottime uint64 // ns since boot
	UID, EUID     uint32
	GID           uint32
	Ptraced       bool
	TracerPID     uint32 // when ptraced: the tracing thread
	TracerTGID    uint32
}

// View is one snapshot of the kernel's tasks.
type View struct {
	List  map[uint64]bool  // processes on init_task.tasks, by task address
	Tree  map[uint64]bool  // processes reached through the process tree
	Tasks map[uint64]*Task // every process and thread read
}

// Snapshot walks the task list and the process tree from initTask (the
// address of init_task), then each process's threads, and reads them.
func Snapshot(m kmem.Memory, l Layout, initTask uint64) (*View, error) {
	v := &View{List: map[uint64]bool{}, Tree: map[uint64]bool{}, Tasks: map[uint64]*Task{}}

	nodes, err := walk(m, initTask+l.tasks, maxProcesses)
	if err != nil {
		return nil, fmt.Errorf("init_task.tasks: %w", err)
	}
	for _, n := range nodes {
		v.List[n-l.tasks] = true
	}

	threads := map[uint64]uint64{} // task -> its thread group leader
	threadsOf := func(leader uint64) ([]uint64, error) {
		ts, err := processThreads(m, l, leader)
		for _, t := range ts {
			threads[t] = leader
		}
		return ts, err
	}

	// Breadth-first down the tree. A child is linked in the children list
	// of the thread that forked it (its real_parent), which in a
	// multithreaded process is often not the leader: every thread's list is
	// walked. A list that fails to walk (its task exiting) only loses that
	// subtree for this snapshot.
	queue := []uint64{initTask}
	seen := map[uint64]bool{initTask: true}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		ts, err := threadsOf(p)
		if err != nil {
			return nil, err
		}
		for _, t := range ts {
			kids, err := walk(m, t+l.children, maxProcesses)
			if err != nil {
				continue
			}
			for _, n := range kids {
				c := n - l.sibling
				if seen[c] {
					continue
				}
				if len(seen) > maxProcesses {
					return nil, errors.New("process tree is larger than any real system: corrupted or looping")
				}
				seen[c] = true
				v.Tree[c] = true
				queue = append(queue, c)
			}
		}
	}
	delete(threads, initTask) // the idle task: not a process
	for a := range v.List {
		if _, done := threads[a]; !done {
			if _, err := threadsOf(a); err != nil {
				return nil, err
			}
		}
	}
	if err := read(m, l, threads, v.Tasks); err != nil {
		return nil, err
	}
	return v, nil
}

// processThreads returns the threads of the process led by leader (the
// leader included), from signal->thread_head. A process exiting under the
// walk yields the leader alone.
func processThreads(m kmem.Memory, l Layout, leader uint64) ([]uint64, error) {
	sigs, ok, err := kmem.ReadU64s(m, []uint64{leader + l.signal})
	if err != nil {
		return nil, err
	}
	if !ok[0] || sigs[0] == 0 {
		return []uint64{leader}, nil
	}
	ts, err := walk(m, sigs[0]+l.threadHead, maxThreads)
	if err != nil {
		return []uint64{leader}, nil
	}
	out := []uint64{leader}
	for _, n := range ts {
		if t := n - l.threadNode; t != leader {
			out = append(out, t)
		}
	}
	return out, nil
}

// walk is kmem.WalkList, retried while the list changes under it.
func walk(m kmem.Memory, head uint64, max int) ([]uint64, error) {
	var err error
	for range walkRetries {
		var nodes []uint64
		if nodes, err = kmem.WalkList(m, head, max); !errors.Is(err, kmem.ErrChanged) {
			return nodes, err
		}
	}
	return nil, err
}

// read fills out with the tasks (task -> leader), in two batched rounds:
// the task_struct fields, then what they point to (parent, tracer, cred).
func read(m kmem.Memory, l Layout, tasks map[uint64]uint64, out map[uint64]*Task) error {
	type field struct {
		off, size uint64
	}
	fields := []field{
		{l.pid, 4}, {l.tgid, 4}, {l.comm, l.commSize}, {l.flags, 4}, {l.mm, 8},
		{l.ptrace, 4}, {l.realParent, 8}, {l.parent, 8}, {l.cred, 8},
		{l.start, 8}, {l.state, min(l.stateSize, 8)},
	}
	addrs := make([]uint64, 0, len(tasks))
	for a := range tasks {
		addrs = append(addrs, a)
	}
	reqs := make([]kmem.Req, 0, len(addrs)*len(fields))
	for _, a := range addrs {
		for _, f := range fields {
			reqs = append(reqs, kmem.Req{Addr: a + f.off, Len: int(f.size)})
		}
	}
	got, err := m.Read(reqs)
	if err != nil {
		return err
	}
	type ptrs struct{ realParent, parent, cred uint64 }
	pending := map[uint64]ptrs{}
	for i, a := range addrs {
		b := got[i*len(fields) : (i+1)*len(fields)]
		if b[0] == nil || b[1] == nil {
			continue // freed between the walk and the read
		}
		t := &Task{
			Addr: a, Leader: tasks[a],
			PID: kmem.U32(b[0]), TGID: kmem.U32(b[1]),
			Flags: kmem.U32(b[3]), HasMM: kmem.U64(b[4]) != 0,
			Ptraced:       kmem.U32(b[5])&PTPtraced != 0,
			StartBoottime: kmem.U64(b[9]),
		}
		copy(t.Comm[:], b[2])
		if s := b[10]; len(s) >= 4 {
			t.State = kmem.U32(s)
		}
		out[a] = t
		pending[a] = ptrs{kmem.U64(b[6]), kmem.U64(b[7]), kmem.U64(b[8])}
	}

	// Second round: parent's TGID, tracer's PID and TGID, credentials.
	addrs = addrs[:0]
	for a := range pending {
		addrs = append(addrs, a)
	}
	reqs = reqs[:0]
	for _, a := range addrs {
		p, t := pending[a], out[a]
		reqs = append(reqs,
			kmem.Req{Addr: p.realParent + l.tgid, Len: 4},
			kmem.Req{Addr: p.cred + l.uid, Len: 4},
			kmem.Req{Addr: p.cred + l.euid, Len: 4},
			kmem.Req{Addr: p.cred + l.gid, Len: 4},
		)
		if t.Ptraced {
			reqs = append(reqs, kmem.Req{Addr: p.parent + l.pid, Len: 4}, kmem.Req{Addr: p.parent + l.tgid, Len: 4})
		} else {
			reqs = append(reqs, kmem.Req{}, kmem.Req{}) // keeps 6 per task; Len 0 is skipped
		}
	}
	got, err = m.Read(reqs)
	if err != nil {
		return err
	}
	for i, a := range addrs {
		b, t := got[i*6:(i+1)*6], out[a]
		t.PPID, t.UID, t.EUID, t.GID = kmem.U32(b[0]), kmem.U32(b[1]), kmem.U32(b[2]), kmem.U32(b[3])
		t.TracerPID, t.TracerTGID = kmem.U32(b[4]), kmem.U32(b[5])
	}
	return nil
}

// maxDepth bounds the walk up the process tree: real hierarchies are a few
// dozen levels deep at most.
const maxDepth = 1024

// FindInitTask walks up the real_parent chain from task (any task, such as
// zygarde's own) to init_task, the only task that is its own parent.
func FindInitTask(m kmem.Memory, l Layout, task uint64) (uint64, error) {
	for range maxDepth {
		vals, ok, err := kmem.ReadU64s(m, []uint64{task + l.realParent})
		if err != nil {
			return 0, err
		}
		if !ok[0] {
			return 0, fmt.Errorf("task %#x is not readable", task)
		}
		if vals[0] == task {
			return task, nil
		}
		task = vals[0]
	}
	return 0, errors.New("no task is its own parent within the process tree's depth: corrupted or looping")
}
