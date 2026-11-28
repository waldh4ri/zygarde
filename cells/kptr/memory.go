// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package kptr

import (
	"errors"
	"os"

	"github.com/cilium/ebpf/btf"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/kmem"
	"github.com/waldh4ri/zygarde/internal/ktask"
)

// Without the task_file iterator (before Linux 5.8), zygarde's own open files
// and the operation tables behind them are read from kernel memory
// (internal/ktask), following the same pointers as kptr.bpf.c.

const (
	procSuperMagic = 0x9fa0
	sIFMT          = 0o170000
	sIFREG         = 0o100000
)

// opsLayout holds the offsets kptr.bpf.c reads through CO-RE.
type opsLayout struct {
	fileFn                          [6]uint64 // llseek, read, read_iter, iterate, iterate_shared, open
	hasIterate                      bool
	iOp, iSb, iMode                 uint64
	inodeFn                         [2]uint64 // lookup, getattr
	sMagic, sType, fsOwner, modName uint64
	seqFile, seqOp                  uint64 // seq_file.{file,op}
	seqFn                           [4]uint64
	hasProc                         bool
	piPde, piVfs                    uint64 // proc_inode.{pde,vfs_inode}
	pdeOps                          uint64 // proc_dir_entry.proc_ops
	procFn                          [4]uint64
	hasReadIter                     bool
	pdeSeq                          uint64 // proc_dir_entry.seq_ops
	hasPdeSeq                       bool
}

func newOpsLayout(spec *btf.Spec) (opsLayout, error) {
	var l opsLayout
	var errs []error
	get := func(typ, path string, dst *uint64) {
		f, err := kmem.Lookup(spec, typ, path)
		if err != nil {
			errs = append(errs, err)
		}
		*dst = f.Offset
	}
	opt := func(typ, path string, dst *uint64) bool {
		f, err := kmem.Lookup(spec, typ, path)
		*dst = f.Offset
		return err == nil
	}
	for i, n := range []string{"llseek", "read", "read_iter", "iterate", "iterate_shared", "open"} {
		if n == "iterate" {
			l.hasIterate = opt("file_operations", n, &l.fileFn[i]) // removed in 6.6
			continue
		}
		get("file_operations", n, &l.fileFn[i])
	}
	get("inode", "i_op", &l.iOp)
	get("inode", "i_sb", &l.iSb)
	get("inode", "i_mode", &l.iMode)
	get("inode_operations", "lookup", &l.inodeFn[0])
	get("inode_operations", "getattr", &l.inodeFn[1])
	get("super_block", "s_magic", &l.sMagic)
	get("super_block", "s_type", &l.sType)
	get("file_system_type", "owner", &l.fsOwner)
	get("module", "name", &l.modName)
	get("seq_file", "file", &l.seqFile)
	get("seq_file", "op", &l.seqOp)
	for i, n := range []string{"start", "next", "stop", "show"} {
		get("seq_operations", n, &l.seqFn[i])
	}
	// procfs internals (fs/proc/internal.h) and proc_ops (Linux 5.6+).
	l.hasProc = opt("proc_inode", "pde", &l.piPde) && opt("proc_inode", "vfs_inode", &l.piVfs) &&
		opt("proc_dir_entry", "proc_ops", &l.pdeOps) &&
		opt("proc_ops", "proc_open", &l.procFn[0]) && opt("proc_ops", "proc_read", &l.procFn[1]) &&
		opt("proc_ops", "proc_lseek", &l.procFn[3])
	if l.hasProc {
		l.hasReadIter = opt("proc_ops", "proc_read_iter", &l.procFn[2])
		l.hasPdeSeq = opt("proc_dir_entry", "seq_ops", &l.pdeSeq)
	}
	return l, errors.Join(errs...)
}

func memorySupported(env *core.Env) error {
	if err := ktask.Supported(env, "BPF task file iterator (Linux 5.8+)"); err != nil {
		return err
	}
	if _, err := ktask.NewFileLayout(env.BTF); err != nil {
		return core.Skip("the kernel's BTF lacks file table fields the memory view needs: %v", err)
	}
	if _, err := newOpsLayout(env.BTF); err != nil {
		return core.Skip("the kernel's BTF lacks operation table fields the memory view needs: %v", err)
	}
	return nil
}

// memoryRead returns, for each of zygarde's own descriptors, the record
// kptr.bpf.c would emit.
func memoryRead(env *core.Env, rec *core.Recorder) ([]kptrOpsRec, error) {
	fl, err := ktask.NewFileLayout(env.BTF)
	if err != nil {
		return nil, err
	}
	ol, err := newOpsLayout(env.BTF)
	if err != nil {
		return nil, err
	}
	src, err := ktask.Open(env, rec)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	view, err := src.Snapshot()
	if err != nil {
		return nil, err
	}
	var self []*ktask.Task
	for _, t := range view.Tasks {
		if t.TGID == uint32(os.Getpid()) {
			self = append(self, t)
		}
	}
	files, err := ktask.Files(src.Mem, fl, self)
	if err != nil {
		return nil, err
	}
	recs := make([]kptrOpsRec, 0, len(files))
	for _, f := range files {
		recs = append(recs, opsRecord(src.Mem, ol, f))
	}
	return recs, nil
}

// opsRecord follows one file's pointers like kptr.bpf.c's dump_ops.
func opsRecord(m kmem.Memory, l opsLayout, f ktask.File) kptrOpsRec {
	r := kptrOpsRec{Fd: f.FD, FileOps: f.Op}
	u64 := func(addr uint64) uint64 {
		if !kmem.Valid(addr, 8) {
			return 0
		}
		v, ok, err := kmem.ReadU64s(m, []uint64{addr})
		if err != nil || !ok[0] {
			return 0
		}
		return v[0]
	}
	if kmem.Valid(r.FileOps, 8) {
		for i, off := range l.fileFn {
			if i == 3 && !l.hasIterate {
				continue
			}
			r.FileFn[i] = u64(r.FileOps + off)
		}
		if l.hasIterate {
			r.Flags |= flagIterate
		}
	}
	inode := f.Inode
	if !kmem.Valid(inode, 8) {
		return r
	}
	r.InodeOps = u64(inode + l.iOp)
	if kmem.Valid(r.InodeOps, 8) {
		r.InodeFn[0] = u64(r.InodeOps + l.inodeFn[0])
		r.InodeFn[1] = u64(r.InodeOps + l.inodeFn[1])
	}
	if sb := u64(inode + l.iSb); kmem.Valid(sb, 8) {
		r.S_magic = u64(sb + l.sMagic)
		if owner := u64(u64(sb+l.sType) + l.fsOwner); kmem.Valid(owner, 8) {
			if got, err := m.Read([]kmem.Req{{Addr: owner + l.modName, Len: len(r.FsOwner)}}); err == nil && got[0] != nil {
				if s, ok := kmem.Prefix(got[0]); ok {
					for i := 0; i < len(s) && i < len(r.FsOwner)-1; i++ {
						r.FsOwner[i] = int8(s[i])
					}
				}
			}
		}
	}
	// seq_file: it points back at the file it serves.
	if kmem.Valid(f.Private, 8) && u64(f.Private+l.seqFile) == f.Addr {
		r.Flags |= flagSeq
		r.SeqOps = u64(f.Private + l.seqOp)
		if kmem.Valid(r.SeqOps, 8) {
			for i, off := range l.seqFn {
				r.SeqFn[i] = u64(r.SeqOps + off)
			}
		}
	}
	// procfs regular files: the proc_dir_entry's own operations.
	if l.hasProc && r.S_magic == procSuperMagic && u64(inode+l.iMode)&sIFMT == sIFREG {
		pde := u64(inode - l.piVfs + l.piPde)
		if kmem.Valid(pde, 8) {
			r.Flags |= flagPDE
			r.Pde = pde
			r.ProcOps = u64(pde + l.pdeOps)
			if kmem.Valid(r.ProcOps, 8) {
				for i, off := range l.procFn {
					if i == 2 && !l.hasReadIter {
						continue
					}
					r.ProcFn[i] = u64(r.ProcOps + off)
				}
			}
			if l.hasPdeSeq {
				r.PdeSeq = u64(pde + l.pdeSeq)
			}
		}
	}
	return r
}
