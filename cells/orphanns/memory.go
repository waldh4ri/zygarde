// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package orphanns

import (
	"github.com/waldh4ri/zygarde/internal/kmem"
	"github.com/waldh4ri/zygarde/internal/ktask"
)

// memoryMembers reads every task's namespaces from kernel memory (internal/
// ktask), as the iterator program reports them: IDs are init-namespace ones,
// which are zygarde's (the memory view requires the initial PID namespace).
func memoryMembers(src *ktask.Source, nsl ktask.NSLayout) (map[nsKey][]member, error) {
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
	recs := make([]orphannsNsRec, 0, len(nss))
	for t, n := range nss {
		r := orphannsNsRec{
			Tgid: t.TGID, Tid: t.PID,
			Mnt: inum(n, "mnt"), Net: inum(n, "net"), Pid: inum(n, "pid"), PidChildren: inum(n, "pid_for_children"),
			Ipc: inum(n, "ipc"), Uts: inum(n, "uts"), User: inum(n, "user"), Cgroup: inum(n, "cgroup"),
			Time: inum(n, "time"), TimeChildren: inum(n, "time_for_children"),
		}
		comm := t.Comm
		if l := view.Tasks[t.Leader]; l != nil {
			comm = l.Comm
		}
		s, _ := kmem.Prefix(comm[:])
		for i := 0; i < len(r.Comm) && i < len(s); i++ {
			r.Comm[i] = int8(s[i])
		}
		recs = append(recs, r)
	}
	return members(recs), nil
}

func inum(n ktask.Namespaces, typ string) uint32 { return uint32(n.Inum[typ]) }
