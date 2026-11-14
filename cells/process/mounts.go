package process

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fsutil"
)

// A process can be hidden without leaving the PID table: mounting an empty
// directory over /proc/<pid> makes every tool that reads /proc/<pid>/* see
// nothing, while the PID still appears in the /proc listing (so the listing
// comparison above stays quiet). Rootkits then rewrite /etc/mtab so `mount`
// does not show it. This file compares the kernel's mount tree (BPF) with the
// userland views of the same mounts: /proc/<pid>/mountinfo, the device number
// of each /proc/<pid>, and /etc/mtab.

const procSuperMagic = 0x9fa0

// maxMountPasses bounds how often the mount iterator is read: with 250 mounts per
// call and one namespace at a time, it covers far more than any host has.
const maxMountPasses = 200

// mountView runs the mount-tree iterator.
type mountView struct {
	prog *ebpf.Program
	seen *ebpf.Map
	walk *ebpf.Map
}

func (v *mountView) Close() {
	v.prog.Close()
	v.seen.Close()
	v.walk.Close()
}

// loadMountView loads the mount iterator on its own so that a kernel whose
// verifier rejects it only costs this check, not the whole Cell.
func loadMountView(env *core.Env, spec *ebpf.CollectionSpec) (*mountView, error) {
	var o struct {
		Dump *ebpf.Program `ebpf:"dump_mounts"`
		Seen *ebpf.Map     `ebpf:"seen_mnt_ns"`
		Walk *ebpf.Map     `ebpf:"walk_state"`
	}
	if err := bpfutil.Load(env, spec, &o); err != nil {
		return nil, err
	}
	return &mountView{prog: o.Dump, seen: o.Seen, walk: o.Walk}, nil
}

// read dumps the mount tree of every mount namespace that has a process.
func (v *mountView) read() ([]processMountRec, error) {
	var keys []uint64
	var k uint64
	it := v.seen.Iterate()
	var val uint8
	for it.Next(&k, &val) {
		keys = append(keys, k)
	}
	for _, k := range keys {
		_ = v.seen.Delete(&k) // the iterator dumps each namespace once per run
	}
	var zero uint32
	if err := v.walk.Put(&zero, make([]byte, v.walk.ValueSize())); err != nil {
		return nil, fmt.Errorf("resetting the mount walk: %w", err)
	}
	// One iterator call writes at most 64 KB, so a large mount tree is dumped over
	// several calls and the iterator is read again until it has nothing more.
	var all []processMountRec
	for pass := 0; pass < maxMountPasses; pass++ {
		data, err := bpfutil.ReadIter(v.prog)
		if err != nil {
			return nil, err
		}
		recs, err := bpfutil.Decode[processMountRec](data)
		if err != nil {
			return nil, err
		}
		if len(recs) == 0 {
			return all, nil
		}
		all = append(all, recs...)
	}
	return all, nil
}

// nsMounts is what the kernel's mount tree holds for one mount namespace.
type nsMounts struct {
	inum      uint32
	mounts    []processMountRec
	claimed   uint32 // mounts the namespace says it has
	visited   uint32 // mounts reached walking the tree
	truncated bool
	roots     []nsRoot // the distinct root mounts of its processes
}

// nsRoot is a mount some process has as its root, and one such process.
type nsRoot struct{ mntID, pid uint32 }

const (
	recMount = 1
	recNS    = 2
	recRoot  = 3
)

// coveredMounts returns the mounts another mount covers at its root (the boot
// root filesystem under the real one): mountinfo never lists those.
// reachableFrom returns the mounts in the subtree of the mount with ID root (a
// process whose root directory is on it sees exactly these). ok is false when
// the root is unknown.
func (n *nsMounts) reachableFrom(root uint32) (map[uint32]bool, bool) {
	if root == 0 {
		return nil, false
	}
	parent := make(map[uint32]uint32, len(n.mounts))
	for _, m := range n.mounts {
		parent[m.MntId] = m.ParentId
	}
	out := map[uint32]bool{}
	for _, m := range n.mounts {
		id := m.MntId
		for i := 0; i < 128; i++ {
			if id == root {
				out[m.MntId] = true
				break
			}
			p, ok := parent[id]
			if !ok || p == id {
				break
			}
			id = p
		}
	}
	return out, true
}

func coveredMounts(ms []processMountRec) map[uint32]bool {
	type key struct {
		parent uint32
		dentry uint64
	}
	over := map[key]bool{}
	for _, m := range ms {
		over[key{m.ParentId, m.Mountpoint}] = true
	}
	out := map[uint32]bool{}
	for _, m := range ms {
		if over[key{m.MntId, m.RootDentry}] {
			out[m.MntId] = true
		}
	}
	return out
}

func groupMounts(recs []processMountRec) map[uint32]*nsMounts {
	out := map[uint32]*nsMounts{}
	get := func(inum uint32) *nsMounts {
		if out[inum] == nil {
			out[inum] = &nsMounts{inum: inum}
		}
		return out[inum]
	}
	for _, r := range recs {
		n := get(r.NsInum)
		switch r.Kind {
		case recMount:
			n.mounts = append(n.mounts, r)
		case recNS:
			n.claimed, n.visited, n.truncated = r.Claimed, r.Visited, r.Truncated != 0
		case recRoot:
			n.roots = append(n.roots, nsRoot{mntID: r.MntId, pid: r.ParentId})
		}
	}
	return out
}

func cstr(a []int8) string {
	b := make([]byte, 0, len(a))
	for _, c := range a {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// procPIDMount reports whether the kernel mount m sits on /proc/<pid> (or
// something below it) inside procfs, and returns the pid and the rest of the
// path under it.
func procPIDMount(m processMountRec) (pid, below string, ok bool) {
	if m.ParentMagic != procSuperMagic || m.PathRoot == 0 || m.PathDepth == 0 || m.PathDepth > uint32(len(m.Path)) {
		return "", "", false
	}
	names := make([]string, m.PathDepth)
	for i := range names {
		names[i] = cstr(m.Path[i][:])
	}
	// Names are innermost first: the last one is directly under the procfs root.
	pid = names[len(names)-1]
	if !isDigits(pid) {
		return "", "", false
	}
	for i := len(names) - 2; i >= 0; i-- {
		below += "/" + names[i]
	}
	return pid, below, true
}

// miEntry is one line of /proc/<pid>/mountinfo.
type miEntry struct {
	id, parent         int
	root, point, fstyp string
	source             string
}

func unescapeOctal(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func parseMountinfo(data string) []miEntry {
	var out []miEntry
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		sep := -1
		for i, x := range f {
			if x == "-" {
				sep = i
				break
			}
		}
		if sep < 6 || sep+2 >= len(f) {
			continue
		}
		id, err1 := strconv.Atoi(f[0])
		parent, err2 := strconv.Atoi(f[1])
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, miEntry{
			id: id, parent: parent, root: unescapeOctal(f[3]), point: unescapeOctal(f[4]),
			fstyp: f[sep+1], source: unescapeOctal(f[sep+2]),
		})
	}
	return out
}

// procPIDPoint returns the pid when a mount point is /proc/<pid> or below it.
func procPIDPoint(point string) (pid, below string, ok bool) {
	rest, found := strings.CutPrefix(point, "/proc/")
	if !found {
		return "", "", false
	}
	pid, below, _ = strings.Cut(rest, "/")
	if !isDigits(pid) {
		return "", "", false
	}
	if below != "" {
		below = "/" + below
	}
	return pid, below, true
}

// mountinfoReaders maps mount namespace inodes to a few processes in them.
func fsName(magic uint32) string {
	switch magic {
	case 0x9fa0:
		return "proc"
	case 0x01021994:
		return "tmpfs"
	case 0xef53:
		return "ext2/3/4"
	case 0x58465342:
		return "xfs"
	case 0x9123683e:
		return "btrfs"
	case 0x794c7630:
		return "overlayfs"
	case 0x62656572:
		return "sysfs"
	case 0x1373:
		return "devfs"
	case 0x858458f6:
		return "ramfs"
	}
	return fmt.Sprintf("0x%x", magic)
}

// mtabState describes /etc/mtab for the evidence of a hidden mount: on
// current systems it is a symlink to /proc/self/mounts, which a rootkit can't
// edit; a regular file can be rewritten to omit mounts.
func mtabState(pid string) string {
	st, err := os.Lstat("/etc/mtab")
	if err != nil {
		return "absent"
	}
	if st.Mode()&os.ModeSymlink != 0 {
		t, _ := os.Readlink("/etc/mtab")
		return "symlink to " + t
	}
	b, err := os.ReadFile("/etc/mtab")
	if err != nil {
		return "regular file (unreadable)"
	}
	if strings.Contains(string(b), " /proc/"+pid+" ") {
		return "regular file, lists the mount"
	}
	return "regular file, does not list the mount"
}

// procMount collects what each view says about one hidden /proc/<pid>.
type procMount struct {
	pid     string
	below   string
	kernel  *processMountRec
	nsInum  uint32
	inInfo  *bool // the kernel has it: do the readers' mountinfo list it? (nil: not compared)
	mountpt string
	views   map[string]bool
}

// missingMount is a kernel mount that mountinfo does not list.
type missingMount struct {
	ns  uint32
	rec processMountRec
}

type taskLookup func(pid uint32) (comm string, ok bool)

// readMountinfo reads and parses /proc/<pid>/mountinfo.
func readMountinfo(procDir string, pid uint32) []miEntry {
	b, err := fsutil.ReadFileNoAtime(filepath.Join(procDir, strconv.FormatUint(uint64(pid), 10), "mountinfo"))
	if err != nil {
		return nil
	}
	return parseMountinfo(string(b))
}

// reading is what one process says the mounts of its namespace are, next to
// the part of the kernel's tree that process should see.
type reading struct {
	ns      *nsMounts
	root    nsRoot
	entries []miEntry
	reach   map[uint32]bool
	ids     map[int]bool
}

// checkProcMounts compares the kernel's mount tree with mountinfo, the device
// numbers of /proc/<pid> and /etc/mtab. tasks resolves a pid of this /proc to
// the kernel's task of that number.
func checkProcMounts(rec *core.Recorder, view *mountView, procDir string, listed map[uint32]bool, tasks taskLookup) error {
	hidden := map[string]*procMount{}
	get := func(pid string) *procMount {
		if hidden[pid] == nil {
			hidden[pid] = &procMount{pid: pid, views: map[string]bool{}}
		}
		return hidden[pid]
	}

	// Kernel view.
	namespaces := map[uint32]*nsMounts{}
	if view != nil {
		if recs, err := view.read(); err != nil {
			rec.Limit("The kernel's mount tree was not compared with /proc: %v", err)
		} else {
			namespaces = groupMounts(recs)
			for _, ns := range namespaces {
				if ns.truncated {
					rec.Limit("The mount tree of mount namespace %d was read only in part (%d mounts reached): mounts beyond that were checked through /proc only", ns.inum, ns.visited)
				}
			}
		}
	}
	inums := make([]uint32, 0, len(namespaces))
	for inum := range namespaces {
		inums = append(inums, inum)
	}
	sort.Slice(inums, func(i, j int) bool { return inums[i] < inums[j] })

	// What a process on each root mount of each namespace reads from mountinfo.
	var selfNS uint32
	var st unix.Stat_t
	supervisor := uint32(os.Getppid())
	if unix.Stat(filepath.Join(procDir, strconv.Itoa(os.Getppid()), "ns", "mnt"), &st) == nil {
		selfNS = uint32(st.Ino)
	}
	var readings []reading
	for _, inum := range inums {
		ns := namespaces[inum]
		for _, root := range ns.roots {
			if root.pid == 0 {
				continue // a process outside Zygarde's PID namespace
			}
			entries := readMountinfo(procDir, root.pid)
			reach, ok := ns.reachableFrom(root.mntID)
			if len(entries) == 0 || !ok {
				continue
			}
			ids := make(map[int]bool, len(entries))
			for _, e := range entries {
				ids[e.id] = true
			}
			readings = append(readings, reading{ns: ns, root: root, entries: entries, reach: reach, ids: ids})
		}
	}

	// Kernel mounts over /proc/<pid>, and whether mountinfo lists them.
	for _, inum := range inums {
		ns := namespaces[inum]
		for i := range ns.mounts {
			m := &ns.mounts[i]
			pid, below, ok := procPIDMount(*m)
			if !ok {
				continue
			}
			pm := get(pid)
			// A namespace cloned from the host's (Zygarde's own worker) repeats its mounts: keep the host's.
			if pm.kernel == nil || inum == selfNS {
				pm.below, pm.kernel, pm.nsInum = below, m, inum
			}
			pm.views["the kernel's mount tree"] = true
			for _, r := range readings {
				if r.ns == ns && r.reach[m.MntId] {
					listedHere := r.ids[int(m.MntId)]
					if pm.inInfo == nil || !listedHere {
						pm.inInfo = &listedHere
					}
				}
			}
		}
	}

	// Kernel mounts that no reader's mountinfo lists, whatever their mount point.
	type nsMount struct{ ns, id uint32 }
	missing := map[nsMount]processMountRec{}
	for _, r := range readings {
		covered := coveredMounts(r.ns.mounts)
		for _, m := range r.ns.mounts {
			if r.reach[m.MntId] && !r.ids[int(m.MntId)] && !covered[m.MntId] && m.ParentId != m.MntId {
				missing[nsMount{r.ns.inum, m.MntId}] = m
			}
		}
	}

	// Userland views: mountinfo's /proc/<pid> mount points, and each /proc/<pid>'s device.
	views := [][]miEntry{readMountinfo(procDir, supervisor)}
	for _, r := range readings {
		views = append(views, r.entries)
	}
	for _, entries := range views {
		for _, e := range entries {
			if pid, below, ok := procPIDPoint(e.point); ok {
				pm := get(pid)
				if pm.kernel == nil {
					pm.below, pm.mountpt = below, e.point
				}
				pm.views["mountinfo"] = true
			}
		}
	}
	var procSt unix.Stat_t
	if unix.Stat(procDir, &procSt) == nil {
		for pid := range listed {
			var s unix.Stat_t
			p := strconv.FormatUint(uint64(pid), 10)
			if unix.Stat(filepath.Join(procDir, p), &s) == nil && s.Dev != procSt.Dev {
				pm := get(p)
				pm.views["the device number of /proc/"+p+" ("+strconv.FormatUint(uint64(s.Dev), 10)+", /proc is "+strconv.FormatUint(uint64(procSt.Dev), 10)+")"] = true
			}
		}
	}

	pids := make([]string, 0, len(hidden))
	for p := range hidden {
		pids = append(pids, p)
	}
	sort.Strings(pids)
	for _, p := range pids {
		reportProcMount(rec, hidden[p], selfNS, tasks)
	}
	list := make([]missingMount, 0, len(missing))
	for k, m := range missing {
		list = append(list, missingMount{ns: k.ns, rec: m})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].ns != list[j].ns {
			return list[i].ns < list[j].ns
		}
		return list[i].rec.MntId < list[j].rec.MntId
	})
	reportMissingMounts(rec, list, hidden)
	reportTreeMismatch(rec, view, namespaces)

	n := 0
	for _, ns := range namespaces {
		n += len(ns.mounts)
	}
	if len(pids) == 0 && len(missing) == 0 && len(namespaces) > 0 {
		rec.Observe(fmt.Sprintf("%d mounts in %d mount namespaces: none over /proc/<pid>, all listed by mountinfo", n, len(namespaces)), nil)
	}
	return nil
}

func reportProcMount(rec *core.Recorder, pm *procMount, selfNS uint32, tasks taskLookup) {
	d := map[string]string{
		"pid":         pm.pid,
		"seen_in":     joinKeys(pm.views),
		"etc_mtab":    mtabState(pm.pid),
		"mount_point": "/proc/" + pm.pid + pm.below,
	}
	comm := ""
	if n, err := strconv.ParseUint(pm.pid, 10, 32); err == nil && pm.nsInum == selfNS && tasks != nil {
		if c, ok := tasks(uint32(n)); ok {
			comm = c
			d["comm"] = c
		}
	}
	if pm.kernel != nil {
		k := pm.kernel
		d["mounted_filesystem"] = fsName(k.Magic)
		d["mounted_directory"] = cstr(k.Root[:])
		d["mount_source"] = cstr(k.Dev[:])
		d["mount_id"] = strconv.FormatUint(uint64(k.MntId), 10)
		d["mount_namespace"] = strconv.FormatUint(uint64(k.NsInum), 10)
	}
	hiddenFromInfo := pm.inInfo != nil && !*pm.inInfo
	if hiddenFromInfo {
		d["hidden_from_mountinfo"] = "yes: the kernel has this mount but /proc/<pid>/mountinfo does not list it"
	}
	who := "process " + pm.pid
	if comm != "" {
		who += " (" + comm + ")"
	}
	desc := fmt.Sprintf("A mount covers /proc/%s%s: %s is hidden from every tool that reads its /proc entry", pm.pid, pm.below, who)
	if pm.below != "" {
		desc = fmt.Sprintf("A mount covers /proc/%s%s: part of %s's /proc entry is hidden from tools", pm.pid, pm.below, who)
	}
	rec.Suspicious(core.Finding{
		Description: desc,
		Details:     d,
		Why: "Nothing mounts over a process's /proc directory in normal operation. A rootkit mounts an empty directory " +
			"(or another process's) there, so ps, top and /proc/<pid>/* read nothing while the PID still appears in the " +
			"/proc listing, then rewrites /etc/mtab or filters mountinfo so the mount does not show.",
		Benign: "None expected. A hardening tool that masks parts of /proc/<pid> (for instance a sandbox) would " +
			"do it for its own processes: check which process created the mount.",
	})
}

func joinKeys(m map[string]bool) string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return strings.Join(k, "; ")
}

// reportMissingMounts flags kernel mounts that the fullest mountinfo of their
// namespace does not list. Mounts over /proc/<pid> are reported above.
func reportMissingMounts(rec *core.Recorder, missing []missingMount, hidden map[string]*procMount) {
	for _, mm := range missing {
		m := mm.rec
		if pid, _, ok := procPIDMount(m); ok && hidden[pid] != nil {
			continue // reported with the process
		}
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("Mount %d (%s on %s) exists in the kernel's mount tree but not in /proc/<pid>/mountinfo", m.MntId, fsName(m.Magic), cstr(m.Root[:])),
			Details: map[string]string{
				"mount_id":        strconv.FormatUint(uint64(m.MntId), 10),
				"parent_mount_id": strconv.FormatUint(uint64(m.ParentId), 10),
				"filesystem":      fsName(m.Magic),
				"source":          cstr(m.Dev[:]),
				"mount_namespace": strconv.FormatUint(uint64(mm.ns), 10),
			},
			Why: "The kernel lists a mount that the mount table every process reads omits. Rootkits filter mountinfo " +
				"(or the code that renders it) to hide the mounts they add.",
			Benign: "A mount outside the root directory of every process in the namespace (for instance after a pivot_root), " +
				"or a mount created or removed while Zygarde was reading.",
		})
	}
}

// reportTreeMismatch compares the number of mounts a namespace says it has with
// the number reachable in its tree.
func reportTreeMismatch(rec *core.Recorder, view *mountView, namespaces map[uint32]*nsMounts) {
	if view == nil {
		return
	}
	var inums []uint32
	for i, ns := range namespaces {
		if !ns.truncated && ns.claimed != 0 && ns.claimed != ns.visited {
			inums = append(inums, i)
		}
	}
	if len(inums) == 0 {
		return
	}
	// A mount or unmount in flight changes either number: look again.
	time.Sleep(300 * time.Millisecond)
	again, err := view.read()
	if err != nil {
		return
	}
	second := groupMounts(again)
	sort.Slice(inums, func(i, j int) bool { return inums[i] < inums[j] })
	for _, inum := range inums {
		a := second[inum]
		b := namespaces[inum]
		if a == nil || a.truncated || a.claimed != b.claimed || a.visited != b.visited || a.claimed == a.visited {
			continue
		}
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("Mount namespace %d counts %d mounts but only %d are linked in its mount tree", inum, a.claimed, a.visited),
			Details: map[string]string{
				"mount_namespace": strconv.FormatUint(uint64(inum), 10),
				"counted":         strconv.FormatUint(uint64(a.claimed), 10),
				"reachable":       strconv.FormatUint(uint64(a.visited), 10),
			},
			Why:    "A mount that the namespace counts but no parent lists was unlinked from the tree, which hides it from anything that walks the tree.",
			Benign: "A lazy unmount (umount -l) in progress leaves a mount counted for a short time.",
		})
	}
}
