// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package ktask

import (
	"errors"

	"github.com/cilium/ebpf/btf"

	"github.com/waldh4ri/zygarde/internal/kmem"
)

// NSLayout holds the offsets to read a task's namespaces, from BTF.
type NSLayout struct {
	// nsproxy members, and the inode number inside each namespace struct.
	members []nsMember
	// User namespace: cred->user_ns->ns.inum. PID namespace: the task's
	// struct pid at its own level, pid->numbers[level].ns->ns.inum.
	credUserNS, userInum         uint64
	pidLevel, pidNumbers, upidNs uint64
	upidSize, pidNsInum          uint64
	hasPid                       bool
}

type nsMember struct {
	name       string // "mnt", "net"...
	nsproxyOff uint64
	inumOff    uint64
}

// NewNSLayout reads the offsets from BTF. Namespaces the kernel lacks
// (time, before 5.6) are left out; the common ones are required.
func NewNSLayout(spec *btf.Spec) (NSLayout, error) {
	var l NSLayout
	var errs []error
	for _, m := range []struct {
		name, field, typ string
		optional         bool
	}{
		{"mnt", "mnt_ns", "mnt_namespace", false},
		{"net", "net_ns", "net", false},
		{"ipc", "ipc_ns", "ipc_namespace", false},
		{"uts", "uts_ns", "uts_namespace", false},
		{"cgroup", "cgroup_ns", "cgroup_namespace", false},
		{"pid_for_children", "pid_ns_for_children", "pid_namespace", false},
		{"time", "time_ns", "time_namespace", true},
		{"time_for_children", "time_ns_for_children", "time_namespace", true},
	} {
		p, err1 := kmem.Lookup(spec, "nsproxy", m.field)
		i, err2 := kmem.Lookup(spec, m.typ, "ns.inum")
		if err := errors.Join(err1, err2); err != nil {
			if !m.optional {
				errs = append(errs, err)
			}
			continue
		}
		l.members = append(l.members, nsMember{m.name, p.Offset, i.Offset})
	}
	get := func(typ, path string) uint64 {
		f, err := kmem.Lookup(spec, typ, path)
		if err != nil {
			errs = append(errs, err)
		}
		return f.Offset
	}
	l.credUserNS = get("cred", "user_ns")
	l.userInum = get("user_namespace", "ns.inum")
	// The PID namespace is optional: it needs task_struct.thread_pid (4.19+).
	lv, e1 := kmem.Lookup(spec, "pid", "level")
	nums, e2 := kmem.Lookup(spec, "pid", "numbers")
	ns, e3 := kmem.Lookup(spec, "upid", "ns")
	size, e4 := kmem.Size(spec, "upid")
	inum, e5 := kmem.Lookup(spec, "pid_namespace", "ns.inum")
	if errors.Join(e1, e2, e3, e4, e5) == nil {
		l.pidLevel, l.pidNumbers, l.upidNs, l.upidSize, l.pidNsInum = lv.Offset, nums.Offset, ns.Offset, size, inum.Offset
		l.hasPid = true
	}
	return l, errors.Join(errs...)
}

// Namespaces are a task's namespaces, by type ("mnt", "net", "pid",
// "user"...), as inode numbers (the nsfs inode, as /proc/<pid>/ns shows).
// NetAddr is the address of its struct net.
type Namespaces struct {
	Inum    map[string]uint64
	NetAddr uint64
}

// ReadNamespaces reads the namespaces of tasks. Tasks without an nsproxy
// (exiting) are left out; a namespace that can't be read is left out of
// that task's map.
func ReadNamespaces(m kmem.Memory, tl Layout, l NSLayout, tasks []*Task) (map[*Task]Namespaces, error) {
	var live []*Task
	for _, t := range tasks {
		if t.NSProxy != 0 {
			live = append(live, t)
		}
	}
	// Round 1: the namespace pointers in nsproxy and cred, and the pid level.
	per := len(l.members) + 2
	reqs := make([]kmem.Req, 0, len(live)*per)
	for _, t := range live {
		for _, mb := range l.members {
			reqs = append(reqs, kmem.Req{Addr: t.NSProxy + mb.nsproxyOff, Len: 8})
		}
		reqs = append(reqs, kmem.Req{Addr: t.Cred + l.credUserNS, Len: 8})
		if l.hasPid && t.ThreadPid != 0 {
			reqs = append(reqs, kmem.Req{Addr: t.ThreadPid + l.pidLevel, Len: 4})
		} else {
			reqs = append(reqs, kmem.Req{})
		}
	}
	got, err := m.Read(reqs)
	if err != nil {
		return nil, err
	}
	// Round 2: each namespace's inode number, and the pid's upid.ns.
	type ptr struct {
		task *Task
		name string
	}
	var ptrs []ptr
	netAddr := map[*Task]uint64{}
	reqs = reqs[:0]
	for i, t := range live {
		b := got[i*per : (i+1)*per]
		for j, mb := range l.members {
			if p := kmem.U64(b[j]); p != 0 {
				if mb.name == "net" {
					netAddr[t] = p
				}
				reqs = append(reqs, kmem.Req{Addr: p + mb.inumOff, Len: 4})
				ptrs = append(ptrs, ptr{t, mb.name})
			}
		}
		if p := kmem.U64(b[len(l.members)]); p != 0 {
			reqs = append(reqs, kmem.Req{Addr: p + l.userInum, Len: 4})
			ptrs = append(ptrs, ptr{t, "user"})
		}
		if lv := b[len(l.members)+1]; lv != nil {
			upid := t.ThreadPid + l.pidNumbers + uint64(kmem.U32(lv))*l.upidSize
			reqs = append(reqs, kmem.Req{Addr: upid + l.upidNs, Len: 8})
			ptrs = append(ptrs, ptr{t, "pid*"}) // the pid_namespace pointer, resolved below
		}
	}
	got, err = m.Read(reqs)
	if err != nil {
		return nil, err
	}
	out := make(map[*Task]Namespaces, len(live))
	ns := func(t *Task) Namespaces {
		n, ok := out[t]
		if !ok {
			n = Namespaces{Inum: map[string]uint64{}}
		}
		return n
	}
	// Round 3: the PID namespace's inode number.
	var pidTasks []*Task
	reqs = reqs[:0]
	for i, p := range ptrs {
		if got[i] == nil {
			continue
		}
		n := ns(p.task)
		switch p.name {
		case "pid*":
			if a := kmem.U64(got[i]); a != 0 {
				reqs = append(reqs, kmem.Req{Addr: a + l.pidNsInum, Len: 4})
				pidTasks = append(pidTasks, p.task)
			}
		default:
			n.Inum[p.name] = uint64(kmem.U32(got[i]))
		}
		out[p.task] = n
	}
	got, err = m.Read(reqs)
	if err != nil {
		return nil, err
	}
	for i, t := range pidTasks {
		if got[i] != nil {
			n := ns(t)
			n.Inum["pid"] = uint64(kmem.U32(got[i]))
			out[t] = n
		}
	}
	// The struct net address, for walks that need more than its inode.
	for t, a := range netAddr {
		if n, ok := out[t]; ok {
			n.NetAddr = a
			out[t] = n
		}
	}
	return out, nil
}
