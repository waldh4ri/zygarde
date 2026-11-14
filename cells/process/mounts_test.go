package process

import "testing"

func name(s string) (a [16]int8) {
	for i := 0; i < len(s); i++ {
		a[i] = int8(s[i])
	}
	return
}

func TestParseMountinfo(t *testing.T) {
	in := `22 28 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw
310 22 8:1 /opt/empty /proc/6178 rw,relatime shared:1 - ext4 /dev/sda1 rw,discard
311 28 8:1 /a\040b /mnt/with\040space rw - ext4 /dev/sda1 rw
bad line
`
	got := parseMountinfo(in)
	if len(got) != 3 {
		t.Fatalf("entries = %d, want 3: %+v", len(got), got)
	}
	if got[1].id != 310 || got[1].parent != 22 || got[1].point != "/proc/6178" || got[1].fstyp != "ext4" || got[1].root != "/opt/empty" {
		t.Errorf("entry = %+v", got[1])
	}
	if got[2].point != "/mnt/with space" || got[2].root != "/a b" {
		t.Errorf("escapes not decoded: %+v", got[2])
	}
}

func TestProcPIDPoint(t *testing.T) {
	for in, want := range map[string]string{
		"/proc/1234":         "1234|",
		"/proc/1234/task":    "1234|/task",
		"/proc/1234/fd/3":    "1234|/fd/3",
		"/proc/sys":          "",
		"/proc/self":         "",
		"/proc":              "",
		"/mnt/proc/1234":     "",
		"/proc/12a4":         "",
		"/sys/kernel/12345":  "",
		"/proc/kcore":        "",
		"/proc/acpi/foo/123": "",
	} {
		pid, below, ok := procPIDPoint(in)
		got := ""
		if ok {
			got = pid + "|" + below
		}
		if got != want {
			t.Errorf("procPIDPoint(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProcPIDMount(t *testing.T) {
	mk := func(parentMagic, depth, root uint32, names ...string) processMountRec {
		m := processMountRec{ParentMagic: parentMagic, PathDepth: depth, PathRoot: root}
		for i, n := range names {
			m.Path[i] = name(n)
		}
		return m
	}
	for _, tc := range []struct {
		name string
		m    processMountRec
		want string
	}{
		{"pid dir", mk(procSuperMagic, 1, 1, "1234"), "1234|"},
		{"below pid", mk(procSuperMagic, 2, 1, "fd", "1234"), "1234|/fd"},
		{"deep", mk(procSuperMagic, 3, 1, "x", "task", "42"), "42|/task/x"},
		{"container mask", mk(procSuperMagic, 1, 1, "kcore"), ""},
		{"proc/sys/kernel", mk(procSuperMagic, 2, 1, "kernel", "sys"), ""},
		{"not procfs", mk(0x1021994, 1, 1, "1234"), ""},
		{"path not complete", mk(procSuperMagic, 4, 0, "a", "b", "c", "1234"), ""},
		{"no names", mk(procSuperMagic, 0, 1), ""},
	} {
		pid, below, ok := procPIDMount(tc.m)
		got := ""
		if ok {
			got = pid + "|" + below
		}
		if got != tc.want {
			t.Errorf("%s: procPIDMount = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestGroupAndReachable(t *testing.T) {
	recs := []processMountRec{
		{Kind: recNS, NsInum: 7, Claimed: 4, Visited: 4},
		{Kind: recMount, NsInum: 7, MntId: 1, ParentId: 1},
		{Kind: recMount, NsInum: 7, MntId: 2, ParentId: 1},
		{Kind: recMount, NsInum: 7, MntId: 3, ParentId: 2},
		{Kind: recMount, NsInum: 7, MntId: 4, ParentId: 1},
		{Kind: recRoot, NsInum: 7, MntId: 2, ParentId: 500}, // pid 500 is on mount 2 (chrooted)
		{Kind: recMount, NsInum: 9, MntId: 10, ParentId: 10},
	}
	g := groupMounts(recs)
	if len(g) != 2 || len(g[7].mounts) != 4 || g[7].claimed != 4 || g[7].visited != 4 || g[7].truncated {
		t.Fatalf("groupMounts = %+v", g[7])
	}
	if len(g[7].roots) != 1 || g[7].roots[0] != (nsRoot{2, 500}) {
		t.Fatalf("roots = %+v", g[7].roots)
	}
	reach, ok := g[7].reachableFrom(g[7].roots[0].mntID)
	if !ok || len(reach) != 2 || !reach[2] || !reach[3] || reach[1] || reach[4] {
		t.Errorf("reachable from 2 = %v", reach)
	}
	if _, ok := g[7].reachableFrom(0); ok {
		t.Error("unknown root should not be reported as reachable")
	}
	all, _ := g[7].reachableFrom(1)
	if len(all) != 4 {
		t.Errorf("reachable from 1 = %v", all)
	}
}

func TestCoveredMounts(t *testing.T) {
	// The boot rootfs (1) is covered at its root by the real root (2), which has /proc (3).
	ms := []processMountRec{
		{MntId: 1, ParentId: 1, Mountpoint: 0, RootDentry: 100},
		{MntId: 2, ParentId: 1, Mountpoint: 100, RootDentry: 200},
		{MntId: 3, ParentId: 2, Mountpoint: 300, RootDentry: 400},
	}
	c := coveredMounts(ms)
	if !c[1] || c[2] || c[3] {
		t.Errorf("coveredMounts = %v, want only mount 1", c)
	}
}

func TestFsName(t *testing.T) {
	if fsName(procSuperMagic) != "proc" || fsName(0xef53) != "ext2/3/4" || fsName(0xabc) != "0xabc" {
		t.Error("fsName")
	}
}
