// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package ktask

import (
	"errors"
	"math/bits"

	"github.com/cilium/ebpf/btf"

	"github.com/waldh4ri/zygarde/internal/kmem"
)

// maxFDs bounds the descriptors read per file table (fs.nr_open is at most
// 1 Mi; tables are allocated to the highest descriptor used).
const maxFDs = 1 << 20

// FileLayout holds the offsets to read open files, from BTF.
type FileLayout struct {
	fdt, maxFds, fd, openFds uint64 // files_struct.fdt, fdtable.{max_fds,fd,open_fds}
	op, private, inode, ino  uint64 // file.{f_op,private_data,f_inode}, inode.i_ino
}

// NewFileLayout reads the offsets from BTF.
func NewFileLayout(spec *btf.Spec) (FileLayout, error) {
	var l FileLayout
	var errs []error
	for _, f := range []struct {
		typ, path string
		dst       *uint64
	}{
		{"files_struct", "fdt", &l.fdt},
		{"fdtable", "max_fds", &l.maxFds}, {"fdtable", "fd", &l.fd}, {"fdtable", "open_fds", &l.openFds},
		{"file", "f_op", &l.op}, {"file", "private_data", &l.private}, {"file", "f_inode", &l.inode},
		{"inode", "i_ino", &l.ino},
	} {
		o, err := kmem.Lookup(spec, f.typ, f.path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		*f.dst = o.Offset
	}
	return l, errors.Join(errs...)
}

// File is one open file of a task.
type File struct {
	Task    *Task  // the task the file table was read from
	FD      uint32 // descriptor number
	Addr    uint64 // struct file
	Op      uint64 // file_operations
	Private uint64 // private_data
	Inode   uint64 // struct inode (f_inode)
	Ino     uint64 // inode number (0 if the inode was unreadable)
}

// Files reads the open files of tasks, once per file table: threads usually
// share their process's (files_struct), and only the first task listed for
// a table is used. Only descriptors set in the table's open_fds bitmap are
// read. A table that changes or vanishes under the read loses only its own
// files.
func Files(m kmem.Memory, l FileLayout, tasks []*Task) ([]File, error) {
	byTable := map[uint64]*Task{}
	var tables []uint64
	for _, t := range tasks {
		if t.Files == 0 {
			continue // exiting
		}
		if _, dup := byTable[t.Files]; !dup {
			byTable[t.Files] = t
			tables = append(tables, t.Files)
		}
	}
	// files_struct -> fdtable -> {max_fds, fd[], open_fds bitmap}.
	fdts, ok, err := kmem.ReadU64s(m, add(tables, l.fdt))
	if err != nil {
		return nil, err
	}
	type table struct {
		task        *Task
		max         uint32
		fd, openFds uint64
		descriptors []uint32
	}
	var tabs []*table
	var reqs []kmem.Req
	for i, f := range tables {
		if ok[i] && fdts[i] != 0 {
			tabs = append(tabs, &table{task: byTable[f]})
			reqs = append(reqs, kmem.Req{Addr: fdts[i] + l.maxFds, Len: 4},
				kmem.Req{Addr: fdts[i] + l.fd, Len: 8}, kmem.Req{Addr: fdts[i] + l.openFds, Len: 8})
		}
	}
	got, err := m.Read(reqs)
	if err != nil {
		return nil, err
	}
	for i, t := range tabs {
		b := got[3*i : 3*i+3]
		t.max, t.fd, t.openFds = min(kmem.U32(b[0]), maxFDs), kmem.U64(b[1]), kmem.U64(b[2])
	}

	// The open_fds bitmaps, in chunks.
	reqs = reqs[:0]
	type chunk struct {
		t     *table
		first uint32 // first descriptor the chunk covers
	}
	var chunks []chunk
	for _, t := range tabs {
		if t.max == 0 || t.fd == 0 || t.openFds == 0 {
			continue
		}
		bytes := uint64(t.max+7) / 8
		for off := uint64(0); off < bytes; off += kmem.ChunkSize {
			n := min(bytes-off, kmem.ChunkSize)
			reqs = append(reqs, kmem.Req{Addr: t.openFds + off, Len: int(n)})
			chunks = append(chunks, chunk{t, uint32(off * 8)})
		}
	}
	got, err = m.Read(reqs)
	if err != nil {
		return nil, err
	}
	for i, c := range chunks {
		for j, by := range got[i] {
			for by != 0 {
				bit := uint32(bits.TrailingZeros8(by))
				by &^= 1 << bit
				if fd := c.first + uint32(j)*8 + bit; fd < c.t.max {
					c.t.descriptors = append(c.t.descriptors, fd)
				}
			}
		}
	}

	// fd[] entries of the open descriptors: struct file pointers.
	reqs = reqs[:0]
	type slot struct {
		t  *table
		fd uint32
	}
	var slots []slot
	for _, t := range tabs {
		for _, fd := range t.descriptors {
			reqs = append(reqs, kmem.Req{Addr: t.fd + 8*uint64(fd), Len: 8})
			slots = append(slots, slot{t, fd})
		}
	}
	got, err = m.Read(reqs)
	if err != nil {
		return nil, err
	}
	var files []File
	for i, s := range slots {
		if p := kmem.U64(got[i]); got[i] != nil && p != 0 {
			files = append(files, File{Task: s.t.task, FD: s.fd, Addr: p})
		}
	}

	// Each file: f_op, private_data, f_inode; then the inode number.
	reqs = reqs[:0]
	for _, f := range files {
		reqs = append(reqs, kmem.Req{Addr: f.Addr + l.op, Len: 8},
			kmem.Req{Addr: f.Addr + l.private, Len: 8}, kmem.Req{Addr: f.Addr + l.inode, Len: 8})
	}
	got, err = m.Read(reqs)
	if err != nil {
		return nil, err
	}
	inodes := make([]uint64, len(files))
	reqs = reqs[:0]
	for i := range files {
		b := got[3*i : 3*i+3]
		files[i].Op, files[i].Private, inodes[i] = kmem.U64(b[0]), kmem.U64(b[1]), kmem.U64(b[2])
		reqs = append(reqs, kmem.Req{Addr: inodes[i] + l.ino, Len: 8})
	}
	got, err = m.Read(reqs)
	if err != nil {
		return nil, err
	}
	out := files[:0]
	for i, f := range files {
		if f.Op == 0 {
			continue // freed under the read
		}
		f.Inode, f.Ino = inodes[i], kmem.U64(got[i])
		out = append(out, f)
	}
	return out, nil
}

func add(addrs []uint64, off uint64) []uint64 {
	out := make([]uint64, len(addrs))
	for i, a := range addrs {
		out[i] = a + off
	}
	return out
}
