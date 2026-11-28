// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package fdowner

import (
	"testing"

	"github.com/waldh4ri/zygarde/internal/kmem"
	"github.com/waldh4ri/zygarde/internal/ktask"
)

func TestReadObjects(t *testing.T) {
	m := kmem.NewFake()
	l := objLayout{
		progAux: 0x10, auxID: 0x4, mapID: 0x20, linkID: 0x8, linkProg: 0x10, perfProg: 0x30,
		sockType: 0x4, sockSk: 0x18, skFamily: 0x10, skNet: 0x30, netInum: 0x80,
		hasLink: true, hasPerf: true, hasNet: true,
	}
	base := uint64(0xffff888000100000)
	next := func() uint64 { base += 0x1000; return base }

	prog, aux := next(), next()
	m.Put64(prog+l.progAux, aux)
	m.Put32(aux+l.auxID, 42)
	mp := next()
	m.Put32(mp+l.mapID, 7)
	lnk := next()
	m.Put32(lnk+l.linkID, 9)
	m.Put64(lnk+l.linkProg, prog)
	perf := next()
	m.Put64(perf+l.perfProg, prog)
	sock, sk, net := next(), next(), next()
	m.Write(sock+l.sockType, []byte{2, 0}) // SOCK_DGRAM
	m.Put64(sock+l.sockSk, sk)
	m.Write(sk+l.skFamily, []byte{10, 0}) // AF_INET6
	m.Put64(sk+l.skNet, net)
	m.Put32(net+l.netInum, 4026531840)

	ops := map[Kind]uint64{Prog: 0xa1, Map: 0xa2, Link: 0xa3, Perf: 0xa4, Socket: 0xa5}
	kinds := map[uint64]Kind{}
	for k, op := range ops {
		kinds[op] = k
	}
	files := []ktask.File{
		{FD: 3, Op: ops[Prog], Private: prog},
		{FD: 4, Op: 0xbeef}, // not a kind of interest
		{FD: 5, Op: ops[Map], Private: mp},
		{FD: 6, Op: ops[Link], Private: lnk},
		{FD: 7, Op: ops[Perf], Private: perf},
		{FD: 8, Op: ops[Socket], Private: sock},
	}
	fds := []FD{{Kind: Prog}, {Kind: Map}, {Kind: Link}, {Kind: Perf}, {Kind: Socket}}
	if err := readObjects(m, l, files, kinds, fds); err != nil {
		t.Fatal(err)
	}
	for i, want := range []FD{
		{Kind: Prog, ID: 42},
		{Kind: Map, ID: 7},
		{Kind: Link, ID: 9, ProgID: 42},
		{Kind: Perf, ProgID: 42},
		{Kind: Socket, SockType: 2, SockFamily: 10, NetNS: 4026531840},
	} {
		if fds[i] != want {
			t.Errorf("fd %d = %+v, want %+v", i, fds[i], want)
		}
	}
}
