// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package fdowner

import (
	"errors"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/kmem"
	"github.com/waldh4ri/zygarde/internal/ktask"
)

// Without the task_file iterator (before Linux 5.8), the descriptors are read
// from kernel memory (internal/ktask): every process's file table, then the
// object behind each file whose file_operations identify a kind of interest.

// objLayout holds the offsets to read the object behind a file, from BTF.
// Offsets of objects the kernel lacks stay 0 and their kind is not read.
type objLayout struct {
	progAux, auxID           uint64 // bpf_prog.aux, bpf_prog_aux.id
	mapID                    uint64 // bpf_map.id
	linkID, linkProg         uint64 // bpf_link.id, .prog (Linux 5.7+)
	perfProg                 uint64 // perf_event.prog (CONFIG_BPF_EVENTS)
	sockType, sockSk         uint64 // socket.type, socket.sk
	skFamily, skNet, netInum uint64 // sock.__sk_common.{skc_family,skc_net.net}, net.ns.inum
	hasLink, hasPerf, hasNet bool
}

func newObjLayout(spec *btf.Spec) (objLayout, error) {
	var l objLayout
	var errs []error
	get := func(typ, path string, dst *uint64) bool {
		f, err := kmem.Lookup(spec, typ, path)
		if err != nil {
			errs = append(errs, err)
			return false
		}
		*dst = f.Offset
		return true
	}
	opt := func(typ, path string, dst *uint64) bool {
		f, err := kmem.Lookup(spec, typ, path)
		*dst = f.Offset
		return err == nil
	}
	get("bpf_prog", "aux", &l.progAux)
	get("bpf_prog_aux", "id", &l.auxID)
	get("bpf_map", "id", &l.mapID)
	get("socket", "type", &l.sockType)
	get("socket", "sk", &l.sockSk)
	get("sock", "__sk_common.skc_family", &l.skFamily)
	l.hasLink = opt("bpf_link", "id", &l.linkID) && opt("bpf_link", "prog", &l.linkProg)
	l.hasPerf = opt("perf_event", "prog", &l.perfProg)
	// skc_net exists only with CONFIG_NET_NS.
	l.hasNet = opt("sock", "__sk_common.skc_net.net", &l.skNet) && opt("net", "ns.inum", &l.netInum)
	return l, errors.Join(errs...)
}

// memorySupported says whether the memory view can run.
func memorySupported(env *core.Env) error {
	if err := ktask.Supported(env, "BPF task file iterator (Linux 5.8+)"); err != nil {
		return err
	}
	if _, err := ktask.NewFileLayout(env.BTF); err != nil {
		return core.Skip("the kernel's BTF lacks file table fields the memory view needs: %v", err)
	}
	if _, err := newObjLayout(env.BTF); err != nil {
		return core.Skip("the kernel's BTF lacks object fields the memory view needs: %v", err)
	}
	return nil
}

// memorySnapshot reads every process's descriptors from kernel memory.
func memorySnapshot(env *core.Env) (*Table, error) {
	fl, err := ktask.NewFileLayout(env.BTF)
	if err != nil {
		return nil, err
	}
	ol, err := newObjLayout(env.BTF)
	if err != nil {
		return nil, err
	}
	src, err := ktask.Open(env, nil)
	if err != nil {
		return nil, err
	}
	defer src.Close()

	// Objects of each kind to learn file_operations from, as zygarde's own
	// descriptors.
	known := map[uint32]Kind{}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.SocketFilter,
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
		License:      "GPL",
	})
	if err != nil {
		return nil, core.WrapBPF("load a program to learn from", err)
	}
	defer prog.Close()
	known[uint32(prog.FD())] = Prog
	if m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1}); err == nil {
		defer m.Close()
		known[uint32(m.FD())] = Map
	}
	if fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0); err == nil {
		defer unix.Close(fd)
		known[uint32(fd)] = Socket
	}
	if f, err := os.Open("/proc/self/ns/net"); err == nil {
		defer f.Close()
		known[uint32(f.Fd())] = NS
	}
	attr := unix.PerfEventAttr{Type: unix.PERF_TYPE_SOFTWARE, Config: unix.PERF_COUNT_SW_DUMMY, Bits: unix.PerfBitDisabled}
	attr.Size = uint32(unsafe.Sizeof(attr))
	if fd, err := unix.PerfEventOpen(&attr, 0, -1, -1, unix.PERF_FLAG_FD_CLOEXEC); err == nil {
		defer unix.Close(fd)
		known[uint32(fd)] = Perf
	}

	view, err := src.Snapshot()
	if err != nil {
		return nil, err
	}
	tasks := make([]*ktask.Task, 0, len(view.Tasks))
	for _, t := range view.Tasks {
		if t.PID != 0 {
			tasks = append(tasks, t)
		}
	}
	files, err := ktask.Files(src.Mem, fl, tasks)
	if err != nil {
		return nil, err
	}

	t := &Table{Learned: map[Kind]bool{}, View: "kernel memory"}
	kinds := map[uint64]Kind{} // file_operations address -> kind
	self := uint32(os.Getpid())
	for _, f := range files {
		if f.Task.TGID != self {
			continue
		}
		if k, ok := known[f.FD]; ok && f.Op != 0 {
			kinds[f.Op] = k
			t.Learned[k] = true
		}
	}
	// Pollable BPF links use a second file_operations table.
	if ks, err := env.Kallsyms(); err == nil {
		if a, ok := ks.Addr("bpf_link_fops_poll"); ok && a != 0 {
			kinds[a] = Link
		}
		if a, ok := ks.Addr("bpf_link_fops"); ok && a != 0 {
			kinds[a] = Link
			t.Learned[Link] = true
		}
	}
	if !t.Learned[Prog] {
		return nil, errors.New("zygarde's own BPF program descriptor was not found in its file table")
	}

	comm := func(task *ktask.Task) string {
		if l := view.Tasks[task.Leader]; l != nil {
			task = l
		}
		s, _ := kmem.Prefix(task.Comm[:])
		return s
	}
	for _, f := range files {
		k, ok := kinds[f.Op]
		if !ok || (k == Link && !ol.hasLink) || (k == Perf && !ol.hasPerf) {
			continue
		}
		fd := FD{TGID: f.Task.TGID, TID: f.Task.PID, FD: f.FD, Kind: k, Comm: comm(f.Task)}
		if k == Socket || k == NS {
			fd.Inode = f.Ino // as the iterator: other kinds share anonymous inodes
		}
		t.FDs = append(t.FDs, fd)
	}
	if err := readObjects(src.Mem, ol, files, kinds, t.FDs); err != nil {
		return nil, err
	}
	// Perf events without a BPF program are of no interest.
	out := t.FDs[:0]
	for _, f := range t.FDs {
		if f.Kind != Perf || f.ProgID != 0 {
			out = append(out, f)
		}
	}
	t.FDs = out
	return t, nil
}

// readObjects fills in the IDs and socket details of fds (built from files,
// in order, keeping only kinds of interest).
func readObjects(m kmem.Memory, l objLayout, files []ktask.File, kinds map[uint64]Kind, fds []FD) error {
	// Private data of each kept file, in the order fds was built.
	var priv []uint64
	for _, f := range files {
		k, ok := kinds[f.Op]
		if !ok || (k == Link && !l.hasLink) || (k == Perf && !l.hasPerf) {
			continue
		}
		priv = append(priv, f.Private)
	}
	// Round 1: what the private data points to.
	type want struct {
		i    int    // index in fds
		what string // field being read
	}
	var reqs []kmem.Req
	var wants []want
	ask := func(i int, what string, addr uint64, n int) {
		if addr == 0 {
			return
		}
		reqs = append(reqs, kmem.Req{Addr: addr, Len: n})
		wants = append(wants, want{i, what})
	}
	for i, f := range fds {
		p := priv[i]
		switch f.Kind {
		case Prog:
			ask(i, "aux", p+l.progAux, 8)
		case Map:
			ask(i, "id", p+l.mapID, 4)
		case Link:
			ask(i, "id", p+l.linkID, 4)
			ask(i, "prog", p+l.linkProg, 8)
		case Perf:
			ask(i, "prog", p+l.perfProg, 8)
		case Socket:
			ask(i, "type", p+l.sockType, 2)
			ask(i, "sk", p+l.sockSk, 8)
		}
	}
	got, err := m.Read(reqs)
	if err != nil {
		return err
	}
	// Round 2: one more hop (aux, prog's aux, the socket's sock).
	reqs, next := reqs[:0], []want{}
	for j, w := range wants {
		b := got[j]
		if b == nil {
			continue
		}
		f := &fds[w.i]
		switch w.what {
		case "id":
			f.ID = kmem.U32(b)
		case "type":
			f.SockType = uint16(kmem.U32(append(b, 0, 0)))
		case "aux": // a program's aux: its ID
			reqs = append(reqs, kmem.Req{Addr: kmem.U64(b) + l.auxID, Len: 4})
			next = append(next, want{w.i, "progid-self"})
		case "prog": // a link's or perf event's program
			if p := kmem.U64(b); p != 0 {
				reqs = append(reqs, kmem.Req{Addr: p + l.progAux, Len: 8})
				next = append(next, want{w.i, "aux-of-prog"})
			}
		case "sk":
			if sk := kmem.U64(b); sk != 0 {
				reqs = append(reqs, kmem.Req{Addr: sk + l.skFamily, Len: 2})
				next = append(next, want{w.i, "family"})
				if l.hasNet {
					reqs = append(reqs, kmem.Req{Addr: sk + l.skNet, Len: 8})
					next = append(next, want{w.i, "net"})
				}
			}
		}
	}
	got, err = m.Read(reqs)
	if err != nil {
		return err
	}
	// Round 3: the last hop (a linked program's ID, the socket's netns inode).
	reqs, last := reqs[:0], []want{}
	for j, w := range next {
		b := got[j]
		if b == nil {
			continue
		}
		f := &fds[w.i]
		switch w.what {
		case "progid-self":
			f.ID = kmem.U32(b)
		case "family":
			f.SockFamily = uint16(kmem.U32(append(b, 0, 0)))
		case "aux-of-prog":
			reqs = append(reqs, kmem.Req{Addr: kmem.U64(b) + l.auxID, Len: 4})
			last = append(last, want{w.i, "progid"})
		case "net":
			if n := kmem.U64(b); n != 0 {
				reqs = append(reqs, kmem.Req{Addr: n + l.netInum, Len: 4})
				last = append(last, want{w.i, "netns"})
			}
		}
	}
	got, err = m.Read(reqs)
	if err != nil {
		return err
	}
	for j, w := range last {
		if b := got[j]; b != nil {
			switch w.what {
			case "progid":
				fds[w.i].ProgID = kmem.U32(b)
			case "netns":
				fds[w.i].NetNS = kmem.U32(b)
			}
		}
	}
	return nil
}
