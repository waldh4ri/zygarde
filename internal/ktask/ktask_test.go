// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package ktask

import (
	"os"
	"testing"

	"github.com/cilium/ebpf/btf"

	"github.com/waldh4ri/zygarde/internal/kmem"
)

// A made-up layout: offsets only need to be distinct and inside the task.
var testLayout = Layout{
	tasks: 0x10, children: 0x20, sibling: 0x30, threadNode: 0x40, signal: 0x50,
	pid: 0x60, tgid: 0x64, comm: 0x70, commSize: 16, flags: 0x80, mm: 0x88,
	ptrace: 0x90, realParent: 0x98, parent: 0xa0, cred: 0xa8, start: 0xb0,
	state: 0xb8, stateSize: 8,
	threadHead: 0x10, uid: 0x4, euid: 0x14, gid: 0x8,
}

type fakeKernel struct {
	*kmem.Fake
	l    Layout
	next uint64
}

func newFakeKernel() *fakeKernel {
	return &fakeKernel{Fake: kmem.NewFake(), l: testLayout, next: 0xffff888000100000}
}

func (k *fakeKernel) alloc() uint64 { a := k.next; k.next += 0x1000; return a }

// list makes a circular list_head at head linking nodes, in order.
func (k *fakeKernel) list(head uint64, nodes ...uint64) {
	all := append([]uint64{head}, nodes...)
	for i, n := range all {
		k.Put64(n, all[(i+1)%len(all)])
		k.Put64(n+8, all[(i+len(all)-1)%len(all)])
	}
}

// task writes a task_struct with its own signal_struct and cred.
func (k *fakeKernel) task(pid, tgid uint32, comm string, parent uint64) uint64 {
	t, sig, cred := k.alloc(), k.alloc(), k.alloc()
	l := k.l
	k.Put32(t+l.pid, pid)
	k.Put32(t+l.tgid, tgid)
	k.PutString(t+l.comm, comm)
	k.Put32(t+l.flags, 0)
	k.Put64(t+l.mm, 0xffff888000aaa000)
	k.Put32(t+l.ptrace, 0)
	k.Put64(t+l.realParent, parent)
	k.Put64(t+l.parent, parent)
	k.Put64(t+l.cred, cred)
	k.Put64(t+l.start, uint64(pid)*1000)
	k.Put64(t+l.state, 1)
	k.Put64(t+l.signal, sig)
	k.Put32(cred+l.uid, 1000+pid)
	k.Put32(cred+l.euid, 2000+pid)
	k.Put32(cred+l.gid, 3000+pid)
	k.list(t + l.children) // no children yet
	return t
}

func TestSnapshot(t *testing.T) {
	k := newFakeKernel()
	l := k.l
	init := k.alloc()
	k.Put32(init+l.pid, 0)
	k.Put32(init+l.tgid, 0)

	sys := k.task(1, 1, "systemd", init)
	web := k.task(100, 100, "nginx", sys)
	worker := k.task(101, 100, "nginx", sys)   // thread of web
	hidden := k.task(200, 200, "implant", sys) // in the tree, unlinked from the task list
	orphan := k.task(300, 300, "odd", sys)     // on the task list, missing from the tree
	traced := k.task(400, 400, "victim", sys)
	k.Put32(traced+l.ptrace, PTPtraced)
	k.Put64(traced+l.parent, web)
	forked := k.task(500, 500, "helper", worker) // forked by a thread, not the leader

	k.list(init+l.tasks, sys+l.tasks, web+l.tasks, orphan+l.tasks, traced+l.tasks)
	k.list(init+l.children, sys+l.sibling)
	k.list(sys+l.children, web+l.sibling, hidden+l.sibling, traced+l.sibling)
	for _, p := range []uint64{sys, hidden, orphan, traced} {
		sig := kmem.U64(read8(t, k, p+l.signal))
		k.list(sig+l.threadHead, p+l.threadNode)
	}
	webSig := kmem.U64(read8(t, k, web+l.signal))
	k.list(webSig+l.threadHead, web+l.threadNode, worker+l.threadNode)
	k.list(worker+l.children, forked+l.sibling)
	forkedSig := kmem.U64(read8(t, k, forked+l.signal))
	k.list(forkedSig+l.threadHead, forked+l.threadNode)
	k.list(init+l.tasks, sys+l.tasks, web+l.tasks, orphan+l.tasks, traced+l.tasks, forked+l.tasks)

	v, err := Snapshot(k, l, init)
	if err != nil {
		t.Fatal(err)
	}
	want := func(set map[uint64]bool, name string, in, out []uint64) {
		t.Helper()
		for _, a := range in {
			if !set[a] {
				t.Errorf("%s lacks task %#x", name, a)
			}
		}
		for _, a := range out {
			if set[a] {
				t.Errorf("%s has task %#x", name, a)
			}
		}
	}
	want(v.List, "task list", []uint64{sys, web, orphan, traced}, []uint64{hidden, worker, init})
	want(v.Tree, "process tree", []uint64{sys, web, hidden, traced, forked}, []uint64{orphan, worker, init})
	if len(v.Tasks) != 7 {
		t.Errorf("read %d tasks, want 7 (6 processes and 1 extra thread)", len(v.Tasks))
	}
	w := v.Tasks[worker]
	if w == nil || w.PID != 101 || w.TGID != 100 || w.Leader != web || w.PPID != 1 || !w.HasMM ||
		w.UID != 1101 || w.EUID != 2101 || w.GID != 3101 || w.StartBoottime != 101000 || w.State != 1 {
		t.Errorf("thread = %+v", w)
	}
	if h := v.Tasks[hidden]; h == nil || string(h.Comm[:7]) != "implant" {
		t.Errorf("hidden process not read: %+v", h)
	}
	if tr := v.Tasks[traced]; tr == nil || !tr.Ptraced || tr.TracerPID != 100 || tr.TracerTGID != 100 {
		t.Errorf("traced = %+v", tr)
	}
	if s := v.Tasks[sys]; s.TracerPID != 0 || s.Ptraced {
		t.Errorf("untraced task has a tracer: %+v", s)
	}
}

// A looping task list is an error, not an endless walk.
func TestSnapshotLoop(t *testing.T) {
	k := newFakeKernel()
	l := k.l
	init := k.alloc()
	a := k.task(1, 1, "a", init)
	b := k.task(2, 2, "b", init)
	// init -> a -> b -> a ... never back to init, with consistent prev links.
	k.Put64(init+l.tasks, a+l.tasks)
	k.Put64(a+l.tasks, b+l.tasks)
	k.Put64(a+l.tasks+8, init+l.tasks)
	k.Put64(b+l.tasks, a+l.tasks)
	k.Put64(b+l.tasks+8, a+l.tasks)
	if _, err := Snapshot(k, l, init); err == nil {
		t.Fatal("looping task list: no error")
	}
}

func read8(t *testing.T, m kmem.Memory, addr uint64) []byte {
	t.Helper()
	got, err := m.Read([]kmem.Req{{Addr: addr, Len: 8}})
	if err != nil || got[0] == nil {
		t.Fatalf("read %#x: %v", addr, err)
	}
	return got[0]
}

// The layout resolves on a real kernel's BTF (the build host's, when it has one).
func TestNewLayoutKernelBTF(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skip("no kernel BTF on this host")
	}
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		t.Skip(err)
	}
	l, err := NewLayout(spec)
	if err != nil {
		t.Fatal(err)
	}
	if l.commSize != 16 || l.stateSize == 0 || l.tasks == 0 || l.cred == 0 || l.start == 0 {
		t.Errorf("layout = %+v", l)
	}
}
