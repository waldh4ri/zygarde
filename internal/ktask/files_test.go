// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package ktask

import (
	"sort"
	"testing"
)

var testFileLayout = FileLayout{fdt: 0x20, maxFds: 0x0, fd: 0x8, openFds: 0x10, op: 0x28, private: 0xc8, inode: 0x20, ino: 0x40}

func TestFiles(t *testing.T) {
	k := newFakeKernel()
	fl := testFileLayout

	// One file table: descriptors 0, 3 and 64 open (crossing a bitmap byte).
	files, fdt, arr, bitmap := k.alloc(), k.alloc(), k.alloc(), k.alloc()
	k.Put64(files+fl.fdt, fdt)
	k.Put32(fdt+fl.maxFds, 128)
	k.Put64(fdt+fl.fd, arr)
	k.Put64(fdt+fl.openFds, bitmap)
	bits := make([]byte, 16)
	bits[0] = 1<<0 | 1<<3
	bits[8] = 1 << 0
	bits[9] = 1 << 1 // fd 73: open in the bitmap but its slot is NULL (being closed)
	k.Write(bitmap, bits)
	for _, fd := range []uint64{0, 3, 64} {
		f, ino := k.alloc(), k.alloc()
		k.Put64(arr+8*fd, f)
		k.Put64(f+fl.op, 0xffffffff81000000+fd)
		k.Put64(f+fl.private, 0xffff888000dd0000+fd)
		k.Put64(f+fl.inode, ino)
		k.Put64(ino+fl.ino, 1000+fd)
	}
	k.Put64(arr+8*73, 0)

	leader := &Task{Addr: 1, PID: 10, TGID: 10, Files: files}
	thread := &Task{Addr: 2, PID: 11, TGID: 10, Files: files} // shares the table
	exiting := &Task{Addr: 3, PID: 12, TGID: 12}              // no table
	got, err := Files(k, fl, []*Task{leader, thread, exiting})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(got, func(i, j int) bool { return got[i].FD < got[j].FD })
	if len(got) != 3 {
		t.Fatalf("read %d files, want 3: %+v", len(got), got)
	}
	for i, fd := range []uint32{0, 3, 64} {
		f := got[i]
		if f.FD != fd || f.Task != leader || f.Op != 0xffffffff81000000+uint64(fd) ||
			f.Private != 0xffff888000dd0000+uint64(fd) || f.Ino != 1000+uint64(fd) {
			t.Errorf("file %d = %+v", fd, f)
		}
	}
}

func TestReadNamespaces(t *testing.T) {
	k := newFakeKernel()
	l := k.l
	nl := NSLayout{
		members: []nsMember{
			{"mnt", 0x08, 0x30}, {"net", 0x10, 0x60}, {"pid_for_children", 0x18, 0x40},
		},
		credUserNS: 0x50, userInum: 0x70,
		pidLevel: 0x4, pidNumbers: 0x40, upidNs: 0x8, upidSize: 0x10, pidNsInum: 0x40, hasPid: true,
	}
	nsproxy, cred, mnt, net, pidc, user, pid, pidNS := k.alloc(), k.alloc(), k.alloc(), k.alloc(), k.alloc(), k.alloc(), k.alloc(), k.alloc()
	k.Put64(nsproxy+0x08, mnt)
	k.Put64(nsproxy+0x10, net)
	k.Put64(nsproxy+0x18, pidc)
	k.Put32(mnt+0x30, 4026531841)
	k.Put32(net+0x60, 4026531840)
	k.Put32(pidc+0x40, 4026531836)
	k.Put64(cred+0x50, user)
	k.Put32(user+0x70, 4026531837)
	k.Put32(pid+0x4, 1)                 // level 1: in a child PID namespace
	k.Put64(pid+0x40+0x10*1+0x8, pidNS) // numbers[1].ns
	k.Put32(pidNS+0x40, 4026532200)

	task := &Task{Addr: 1, PID: 5, NSProxy: nsproxy, Cred: cred, ThreadPid: pid}
	gone := &Task{Addr: 2, PID: 6} // exiting: no nsproxy
	got, err := ReadNamespaces(k, l, nl, []*Task{task, gone})
	if err != nil {
		t.Fatal(err)
	}
	n, ok := got[task]
	if !ok {
		t.Fatal("task not read")
	}
	want := map[string]uint64{"mnt": 4026531841, "net": 4026531840, "pid_for_children": 4026531836, "user": 4026531837, "pid": 4026532200}
	for name, v := range want {
		if n.Inum[name] != v {
			t.Errorf("%s = %d, want %d", name, n.Inum[name], v)
		}
	}
	if n.NetAddr != net {
		t.Errorf("NetAddr = %#x, want %#x", n.NetAddr, net)
	}
	if _, ok := got[gone]; ok {
		t.Error("exiting task without nsproxy was read")
	}
}
