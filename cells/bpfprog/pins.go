// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package bpfprog

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/fdowner"
	"github.com/waldh4ri/zygarde/internal/fsutil"
)

// pin is an object pinned in a BPF filesystem.
type pin struct {
	Path   string // as seen in the mount namespace of the BPF filesystem
	Kind   fdowner.Kind
	ID     uint32
	Name   string // programs and maps
	ProgID uint32 // links: the program they run
	Mount  *bpffsMount
}

// bpffsMount is one BPF filesystem instance, found in some mount namespace.
type bpffsMount struct {
	Point string // mount point, in its namespace
	Walk  string // the same directory, reachable from zygarde
	MntNS string // mount namespace ("mnt:[...]"), "" for zygarde's own
	PID   string // a process of that namespace
}

// maxMountNS bounds how many other mount namespaces are searched for BPF filesystems.
const maxMountNS = 256

// bpffsMounts lists every BPF filesystem mounted in zygarde's mount namespace
// (a copy of the host's) and in the mount namespaces of running processes.
// Each filesystem instance is listed once. A pin keeps a program loaded with
// no process holding it, so a loader can hide its pins in a BPF filesystem
// mounted somewhere unusual, or only in a private mount namespace.
func bpffsMounts() []bpffsMount {
	var out []bpffsMount
	seen := map[string]bool{} // device and root inside the filesystem: one instance, bind mounts included
	add := func(mountinfo, ns, pid, prefix string) {
		data, err := fsutil.ReadFileNoAtime(mountinfo)
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			pre, post, ok := strings.Cut(line, " - ")
			if !ok {
				continue
			}
			pf, qf := strings.Fields(pre), strings.Fields(post)
			if len(pf) < 5 || len(qf) < 1 || qf[0] != "bpf" {
				continue
			}
			key := pf[2] + " " + pf[3]
			if seen[key] {
				continue
			}
			seen[key] = true
			point := unescapeMount(pf[4])
			out = append(out, bpffsMount{Point: point, Walk: filepath.Join(prefix, point), MntNS: ns, PID: pid})
		}
	}
	add("/proc/self/mountinfo", "", "", "")
	self, _ := os.Readlink("/proc/self/ns/mnt")
	parent, _ := os.Readlink("/proc/" + strconv.Itoa(os.Getppid()) + "/ns/mnt")
	nss := map[string]bool{self: true, parent: true}
	entries, err := fsutil.ReadDirNoAtime("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		ns, err := os.Readlink("/proc/" + e.Name() + "/ns/mnt")
		if err != nil || nss[ns] {
			continue
		}
		if len(nss) >= maxMountNS+2 {
			break
		}
		nss[ns] = true
		add("/proc/"+e.Name()+"/mountinfo", ns, e.Name(), "/proc/"+e.Name()+"/root")
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].MntNS == "" && out[j].MntNS != "" })
	return out
}

// unescapeMount decodes the octal escapes (\040 for a space) of mountinfo fields.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// unusualMount says why a BPF filesystem's mount point is an odd place for
// one, or returns "". Tools mount it at /sys/fs/bpf (also inside containers).
func unusualMount(point string) string {
	under := func(d string) bool { return point == d || strings.HasPrefix(point, d+"/") }
	switch {
	case under("/dev/shm"), under("/run/shm"):
		return "a memory-backed directory"
	case under("/tmp"), under("/var/tmp"):
		return "a temporary directory"
	}
	for _, part := range strings.Split(point, "/") {
		if strings.HasPrefix(part, ".") && part != "." && part != ".." {
			return "a hidden directory"
		}
	}
	return ""
}

// pins lists every program, map and link pinned in the given BPF filesystems.
func pins(mounts []bpffsMount) []pin {
	var out []pin
	for i := range mounts {
		m := &mounts[i]
		var st unix.Statfs_t
		if unix.Statfs(m.Walk, &st) != nil || st.Type != unix.BPF_FS_MAGIC {
			continue // unmounted meanwhile, or the namespace's process exited
		}
		_ = filepath.WalkDir(m.Walk, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			shown := filepath.Join(m.Point, strings.TrimPrefix(path, m.Walk))
			// Programs and links can only be opened read-write; maps read-only.
			if p, err := ebpf.LoadPinnedProgram(path, nil); err == nil {
				defer p.Close()
				if info, err := p.Info(); err == nil {
					id, _ := info.ID()
					out = append(out, pin{Path: shown, Kind: fdowner.Prog, ID: uint32(id), Name: info.Name, Mount: m})
				}
				return nil
			}
			if mp, err := ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{ReadOnly: true}); err == nil {
				defer mp.Close()
				if info, err := mp.Info(); err == nil {
					id, _ := info.ID()
					out = append(out, pin{Path: shown, Kind: fdowner.Map, ID: uint32(id), Name: info.Name, Mount: m})
				}
				return nil
			}
			if l, err := link.LoadPinnedLink(path, nil); err == nil {
				defer l.Close()
				if info, err := l.Info(); err == nil {
					out = append(out, pin{Path: shown, Kind: fdowner.Link, ID: uint32(info.ID), ProgID: uint32(info.Program), Mount: m})
				}
			}
			return nil
		})
	}
	return out
}

// pinnedProgs maps program IDs to a path that keeps them loaded: the program
// itself or a link running it.
func pinnedProgs(ps []pin) map[uint32]string {
	out := map[uint32]string{}
	for _, p := range ps {
		switch p.Kind {
		case fdowner.Prog:
			out[p.ID] = p.Path
		case fdowner.Link:
			if _, ok := out[p.ProgID]; !ok {
				out[p.ProgID] = p.Path
			}
		}
	}
	return out
}
