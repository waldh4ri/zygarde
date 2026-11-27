// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

// Package kmem reads kernel memory from userspace through a BPF program, so
// Cells can walk kernel structures (lists, trees) with member offsets taken
// from the running kernel's BTF: what crash(8) does with /proc/kcore and
// DWARF debug info, without debug info.
//
// Reads use bpf_probe_read_kernel(), which fails instead of faulting on freed
// or unmapped memory, so following a pointer a rootkit left dangling cannot
// oops the kernel. Addresses outside the kernel half of the address space and
// the x86-64 vsyscall page are refused before they reach the kernel.
package kmem

//go:generate go tool bpf2go -target amd64,arm64 -cflags "-Wall -Werror -Wno-missing-declarations" -type kmem_req -type kmem_chunk kmem kmem.bpf.c -- -I../../bpf/include

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sync"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/core"
)

const (
	maxReads = 64 // MAX_READS in kmem.bpf.c
	// ChunkSize is the most one Req may read (CHUNK in kmem.bpf.c).
	ChunkSize = 256
)

// Req asks for Len bytes (1 to ChunkSize) at kernel address Addr.
type Req struct {
	Addr uint64
	Len  int
}

// Memory reads kernel memory. Each result is the bytes read, or nil when the
// address was refused or could not be read.
type Memory interface {
	Read(reqs []Req) ([][]byte, error)
}

// Reader is a Memory backed by the BPF program. It is safe for concurrent use.
type Reader struct {
	mu   sync.Mutex
	objs kmemObjects
	kp   link.Link
	seq  uint32
	id   uint32
}

// Open loads and attaches the reader. Callers must Close it.
func Open(env *core.Env) (*Reader, error) {
	if env.Lockdown == "confidentiality" {
		return nil, errors.New("kernel lockdown (confidentiality)")
	}
	spec, err := loadKmem()
	if err != nil {
		return nil, err
	}
	if err := bpfutil.SetTarget(env, spec); err != nil {
		return nil, err
	}
	r := &Reader{}
	if err := bpfutil.Load(env, spec, &r.objs); err != nil {
		return nil, err
	}
	if id, err := bpfutil.ProgramID(r.objs.ReadKmem); err == nil {
		r.id = id
	}
	if r.kp, err = link.Kprobe("sys_getuid", r.objs.ReadKmem, nil); err != nil {
		r.objs.Close()
		return nil, core.WrapBPF("attach kprobe sys_getuid", err)
	}
	return r, nil
}

// ProgramID is the BPF program's ID (0 if unknown), for the scan footprint.
func (r *Reader) ProgramID() uint32 { return r.id }

// Close detaches and unloads the reader.
func (r *Reader) Close() error {
	err := r.kp.Close()
	return errors.Join(err, r.objs.Close())
}

// Read performs the requests, ChunkSize-limited, in batches of 64.
func (r *Reader) Read(reqs []Req) ([][]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]byte, len(reqs))
	var slots []int // indexes into reqs of the current batch
	flush := func() error {
		if len(slots) == 0 {
			return nil
		}
		err := r.batch(reqs, slots, out)
		slots = slots[:0]
		return err
	}
	for i, q := range reqs {
		if q.Len <= 0 || q.Len > ChunkSize || !Valid(q.Addr, q.Len) {
			continue
		}
		slots = append(slots, i)
		if len(slots) == maxReads {
			if err := flush(); err != nil {
				return nil, err
			}
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Reader) batch(reqs []Req, slots []int, out [][]byte) error {
	r.seq++
	seq := r.seq
	for k, i := range slots {
		q := kmemKmemReq{Addr: reqs[i].Addr, Len: uint32(reqs[i].Len), Seq: seq}
		if err := r.objs.Reqs.Put(uint32(k), q); err != nil {
			return core.WrapBPF("write read requests", err)
		}
	}
	if len(slots) < maxReads {
		if err := r.objs.Reqs.Put(uint32(len(slots)), kmemKmemReq{}); err != nil {
			return core.WrapBPF("write read requests", err)
		}
	}
	var c kmemKmemChunk
	fired := false
	for attempt := 0; attempt < 3 && !fired; attempt++ {
		unix.Getuid()
		if err := r.objs.Chunks.Lookup(uint32(0), &c); err != nil {
			return core.WrapBPF("read results", err)
		}
		fired = c.Seq == seq
	}
	if !fired {
		return errors.New("the kprobe on getuid() never fired")
	}
	for k, i := range slots {
		if k > 0 {
			if err := r.objs.Chunks.Lookup(uint32(k), &c); err != nil {
				return core.WrapBPF("read results", err)
			}
		}
		if c.Seq != seq {
			return fmt.Errorf("read %d of the batch did not run", k)
		}
		if c.Err == 0 {
			out[i] = append([]byte(nil), c.Data[:reqs[i].Len]...)
		}
	}
	return nil
}

// vsyscallPage is the x86-64 legacy vsyscall page: reading it from BPF oopses
// kernels without commit 32019c659ecf (see kernel.Image).
const vsyscallPage = 0xffffffffff600000

// Valid reports whether [addr, addr+n) may be read: inside the kernel half of
// the address space (where every kernel object lives) and clear of the
// vsyscall page. Pointers read from kernel memory are untrusted, so every
// address is checked before it is followed.
func Valid(addr uint64, n int) bool {
	if n <= 0 {
		return false
	}
	end := addr + uint64(n)
	if end < addr {
		return false
	}
	lowest := uint64(0xffff800000000000) // x86-64: canonical kernel half, 4- and 5-level paging
	if runtime.GOARCH == "arm64" {
		lowest = 0xfff0000000000000 // arm64: up to 52-bit kernel VAs
	}
	if addr < lowest {
		return false
	}
	return runtime.GOARCH != "amd64" || end <= vsyscallPage || addr >= vsyscallPage+4096
}

// U64 decodes a little-endian pointer or 64-bit value (amd64 and arm64).
func U64(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return binary.LittleEndian.Uint64(b)
}

// U32 decodes a little-endian 32-bit value.
func U32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}

// String decodes a NUL-terminated string, possibly empty. ok is false when b
// holds no NUL or a byte that is neither printable ASCII nor a tab or newline
// (linux_banner ends with one), as when a pointer leads to freed or reused
// memory.
func String(b []byte) (s string, ok bool) {
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), true
		}
		if (c < 0x20 && c != '\n' && c != '\t') || c > 0x7e {
			return "", false
		}
	}
	return "", false
}

// Prefix decodes the start of a string that may be longer than b, as String
// does but accepting a missing NUL. It suits strings checked by their prefix
// (linux_banner is longer than ChunkSize on some kernels).
func Prefix(b []byte) (s string, ok bool) {
	if s, ok := String(b); ok {
		return s, true
	}
	if _, ok := String(append(append([]byte(nil), b...), 0)); !ok {
		return "", false
	}
	return string(b), true
}

// ReadU64s reads one pointer-sized value at each address; missing results are
// reported with ok[i] false.
func ReadU64s(m Memory, addrs []uint64) (vals []uint64, ok []bool, err error) {
	reqs := make([]Req, len(addrs))
	for i, a := range addrs {
		reqs[i] = Req{a, 8}
	}
	got, err := m.Read(reqs)
	if err != nil {
		return nil, nil, err
	}
	vals, ok = make([]uint64, len(addrs)), make([]bool, len(addrs))
	for i, b := range got {
		if b != nil {
			vals[i], ok[i] = U64(b), true
		}
	}
	return vals, ok, nil
}

// ReadStrings reads a NUL-terminated string of at most max bytes (up to
// ChunkSize) at each address. Unreadable or malformed strings are reported
// with ok[i] false.
func ReadStrings(m Memory, addrs []uint64, max int) (strs []string, ok []bool, err error) {
	if max > ChunkSize {
		max = ChunkSize
	}
	reqs := make([]Req, len(addrs))
	for i, a := range addrs {
		// Don't cross into the next page: the string may end just before an
		// unmapped one, and the whole read would fail.
		n := max
		if room := 4096 - int(a%4096); room < n {
			n = room
		}
		reqs[i] = Req{a, n}
	}
	got, err := m.Read(reqs)
	if err != nil {
		return nil, nil, err
	}
	strs, ok = make([]string, len(addrs)), make([]bool, len(addrs))
	for i, b := range got {
		if b != nil {
			strs[i], ok[i] = String(b)
		}
	}
	return strs, ok, nil
}

// ErrChanged means a list changed while it was walked.
var ErrChanged = errors.New("list changed while it was walked")

// WalkList follows a kernel struct list_head from head and returns the
// address of every element's list_head, checking each element's prev pointer
// so a list changing under the walk, or a forged link, is noticed. It reads
// one element per batch: each address depends on the previous read.
func WalkList(m Memory, head uint64, max int) ([]uint64, error) {
	got, err := m.Read([]Req{{head, 16}})
	if err != nil {
		return nil, err
	}
	if got[0] == nil {
		return nil, fmt.Errorf("list head %#x is not readable", head)
	}
	var nodes []uint64
	prev, cur := head, U64(got[0][:8])
	for cur != head {
		if len(nodes) >= max {
			return nil, fmt.Errorf("list at %#x has more than %d elements or a loop", head, max)
		}
		got, err := m.Read([]Req{{cur, 16}})
		if err != nil {
			return nil, err
		}
		if got[0] == nil {
			return nil, fmt.Errorf("list element %#x is not readable", cur)
		}
		if U64(got[0][8:16]) != prev {
			return nil, ErrChanged
		}
		nodes = append(nodes, cur)
		prev, cur = cur, U64(got[0][:8])
	}
	return nodes, nil
}
