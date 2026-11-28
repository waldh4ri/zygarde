// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package netfilter

import (
	"errors"
	"sort"

	"github.com/cilium/ebpf/btf"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/kmem"
	"github.com/waldh4ri/zygarde/internal/ktask"
)

// Without the task iterator (before Linux 5.8), the namespaces and their
// hooks are read from kernel memory (internal/ktask): every task's network
// namespace, then in each struct net the same chains the iterator reads.

// maxDevs bounds the devices walked per namespace.
const maxDevs = 4096

// nfLayout holds the offsets to read a namespace's hooks, from BTF.
type nfLayout struct {
	families              []nfFamily
	entryNum, entryHooks  uint64 // nf_hook_entries.{num_hook_entries,hooks}
	devHead, devList      uint64 // net.dev_base_head, net_device.dev_list
	devIfindex, devName   uint64
	ingress, egress       uint64 // net_device.nf_hooks_{ingress,egress}
	hasIngress, hasEgress bool
}

// nfFamily is one array of hook chains in struct net (net.nf.hooks_ipv4...).
type nfFamily struct {
	pf    uint8
	off   uint64
	hooks int
}

func newNFLayout(spec *btf.Spec) (nfLayout, error) {
	var l nfLayout
	var errs []error
	for _, f := range []struct {
		pf       uint8
		member   string
		hooks    int
		optional bool
	}{
		{nfprotoIPv4, "nf.hooks_ipv4", 5, false},
		{nfprotoIPv6, "nf.hooks_ipv6", 5, true},
		{nfprotoARP, "nf.hooks_arp", 3, true},
		{nfprotoBridge, "nf.hooks_bridge", 5, true},
	} {
		o, err := kmem.Lookup(spec, "net", f.member)
		if err != nil {
			if !f.optional {
				errs = append(errs, err)
			}
			continue
		}
		l.families = append(l.families, nfFamily{f.pf, o.Offset, f.hooks})
	}
	for _, f := range []struct {
		typ, path string
		dst       *uint64
	}{
		{"nf_hook_entries", "num_hook_entries", &l.entryNum},
		{"nf_hook_entries", "hooks", &l.entryHooks},
		{"net", "dev_base_head", &l.devHead},
		{"net_device", "dev_list", &l.devList},
		{"net_device", "ifindex", &l.devIfindex},
		{"net_device", "name", &l.devName},
	} {
		o, err := kmem.Lookup(spec, f.typ, f.path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		*f.dst = o.Offset
	}
	if o, err := kmem.Lookup(spec, "net_device", "nf_hooks_ingress"); err == nil {
		l.ingress, l.hasIngress = o.Offset, true
	}
	if o, err := kmem.Lookup(spec, "net_device", "nf_hooks_egress"); err == nil {
		l.egress, l.hasEgress = o.Offset, true
	}
	return l, errors.Join(errs...)
}

func memorySupported(env *core.Env) error {
	if err := ktask.Supported(env, "BPF task iterator (Linux 5.8+)"); err != nil {
		return err
	}
	if _, err := ktask.NewNSLayout(env.BTF); err != nil {
		return core.Skip("the kernel's BTF lacks namespace fields the memory view needs: %v", err)
	}
	if _, err := newNFLayout(env.BTF); err != nil {
		return core.Skip("the kernel's BTF lacks netfilter fields the memory view needs: %v", err)
	}
	return nil
}

// memoryRecords reads, for every network namespace a task is in, the
// records the iterator program would emit.
func memoryRecords(env *core.Env, rec *core.Recorder) ([]netfilterNfRec, error) {
	nsl, err := ktask.NewNSLayout(env.BTF)
	if err != nil {
		return nil, err
	}
	nfl, err := newNFLayout(env.BTF)
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
	tasks := make([]*ktask.Task, 0, len(view.Tasks))
	for _, t := range view.Tasks {
		if t.PID != 0 {
			tasks = append(tasks, t)
		}
	}
	nss, err := ktask.ReadNamespaces(src.Mem, src.Layout, nsl, tasks)
	if err != nil {
		return nil, err
	}
	nets := map[uint64]uint32{} // struct net -> namespace inode
	for _, n := range nss {
		if n.NetAddr != 0 && n.Inum["net"] != 0 {
			nets[n.NetAddr] = uint32(n.Inum["net"])
		}
	}
	addrs := make([]uint64, 0, len(nets))
	for a := range nets {
		addrs = append(addrs, a)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i] < addrs[j] })

	var recs []netfilterNfRec
	for _, net := range addrs {
		r, err := readNamespace(src.Mem, nfl, net, nets[net])
		if err != nil {
			return nil, err
		}
		recs = append(recs, r...)
	}
	return recs, nil
}

// readNamespace reads one namespace's chains, then its devices' chains, and
// ends with the namespace record, like the iterator program.
func readNamespace(m kmem.Memory, l nfLayout, net uint64, inum uint32) ([]netfilterNfRec, error) {
	type chain struct {
		pf, hook uint8
		ifindex  uint32
		dev      string
		entries  uint64
	}
	var chains []chain
	var reqs []kmem.Req
	var where []chain
	for _, f := range l.families {
		for h := 0; h < f.hooks; h++ {
			reqs = append(reqs, kmem.Req{Addr: net + f.off + 8*uint64(h), Len: 8})
			where = append(where, chain{pf: f.pf, hook: uint8(h)})
		}
	}
	got, err := m.Read(reqs)
	if err != nil {
		return nil, err
	}
	for i, c := range where {
		if e := kmem.U64(got[i]); got[i] != nil && e != 0 {
			c.entries = e
			chains = append(chains, c)
		}
	}

	flags := uint8(0)
	if l.hasIngress {
		nodes, err := kmem.WalkList(m, net+l.devHead, maxDevs)
		if err != nil && !errors.Is(err, kmem.ErrChanged) {
			return nil, err
		}
		if err != nil {
			flags |= flagTruncated // the device list changed under the walk
		}
		for _, n := range nodes {
			dev := n - l.devList
			reqs = []kmem.Req{{Addr: dev + l.devIfindex, Len: 4}, {Addr: dev + l.devName, Len: 16}, {Addr: dev + l.ingress, Len: 8}}
			if l.hasEgress {
				reqs = append(reqs, kmem.Req{Addr: dev + l.egress, Len: 8})
			}
			got, err := m.Read(reqs)
			if err != nil {
				return nil, err
			}
			name, _ := kmem.Prefix(got[1])
			for i, hook := range []uint8{0, 1} {
				if 2+i < len(got) && got[2+i] != nil && kmem.U64(got[2+i]) != 0 {
					chains = append(chains, chain{pf: nfprotoNetdev, hook: hook, ifindex: kmem.U32(got[0]), dev: name, entries: kmem.U64(got[2+i])})
				}
			}
		}
	} else {
		flags |= flagNoDevHooks
	}

	// Each chain: its entry count and up to maxHooks {hook, priv} pairs.
	reqs = reqs[:0]
	for _, c := range chains {
		reqs = append(reqs, kmem.Req{Addr: c.entries + l.entryNum, Len: 2})
	}
	got, err = m.Read(reqs)
	if err != nil {
		return nil, err
	}
	var out []netfilterNfRec
	for i, c := range chains {
		if got[i] == nil {
			continue
		}
		r := netfilterNfRec{Inum: inum, Kind: recChain, Pf: c.pf, Hook: c.hook, Ifindex: c.ifindex, Entries: c.entries}
		r.Num = uint32(got[i][0]) | uint32(got[i][1])<<8
		for j, ch := range []byte(c.dev) {
			if j < len(r.Dev) {
				r.Dev[j] = int8(ch)
			}
		}
		n := min(int(r.Num), maxHooks)
		pairs, err := readPairs(m, c.entries+l.entryHooks, n)
		if err != nil {
			return nil, err
		}
		copy(r.Hooks[:], pairs)
		out = append(out, r)
	}
	return append(out, netfilterNfRec{Inum: inum, Kind: recNetns, Flags: flags}), nil
}

// readPairs reads n {hook, priv} pairs (16 bytes each) from addr.
func readPairs(m kmem.Memory, addr uint64, n int) ([]uint64, error) {
	var reqs []kmem.Req
	for off := 0; off < 16*n; off += kmem.ChunkSize {
		reqs = append(reqs, kmem.Req{Addr: addr + uint64(off), Len: min(kmem.ChunkSize, 16*n-off)})
	}
	got, err := m.Read(reqs)
	if err != nil {
		return nil, err
	}
	var out []uint64
	for _, b := range got {
		if b == nil {
			break
		}
		for i := 0; i+8 <= len(b); i += 8 {
			out = append(out, kmem.U64(b[i:]))
		}
	}
	return out, nil
}
