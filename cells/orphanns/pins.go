package orphanns

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fdowner"
	"github.com/waldh4ri/zygarde/internal/fsutil"
)

// pin is something that keeps a namespace alive besides a process in it.
type pin struct {
	key   nsKey
	how   string // "bind mount" or "descriptor"
	where string // the mount point, or "descriptor N"
	pid   uint32 // the process whose view showed it (mount) or that holds it (descriptor)
	comm  string
	fd    int
}

// nsLink matches what readlink returns for a namespace file: "net:[4026531833]".
var nsLink = regexp.MustCompile(`^(mnt|net|pid|ipc|uts|user|cgroup|time):\[(\d+)\]$`)

func parseNSLink(s string) (nsKey, bool) {
	m := nsLink.FindStringSubmatch(s)
	if m == nil {
		return nsKey{}, false
	}
	inum, err := strconv.ParseUint(m[2], 10, 64)
	return nsKey{m[1], inum}, err == nil
}

// parseNSFSMounts returns the nsfs mounts of a mountinfo file: for a bind
// mount of a namespace file, the root field is "net:[4026532260]" and the
// filesystem type is nsfs.
func parseNSFSMounts(mountinfo string) []pin {
	var out []pin
	for _, line := range strings.Split(mountinfo, "\n") {
		f := strings.Fields(line)
		sep := -1
		for i, x := range f {
			if x == "-" {
				sep = i
				break
			}
		}
		if sep < 6 || sep+1 >= len(f) || f[sep+1] != "nsfs" {
			continue
		}
		key, ok := parseNSLink(unescapeOctal(f[3]))
		if !ok {
			continue
		}
		out = append(out, pin{key: key, how: "bind mount", where: unescapeOctal(f[4])})
	}
	return out
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

// mountPins lists the nsfs bind mounts visible from one process of each mount
// namespace (a bind mount lives in the mount namespace that made it).
func (c *Cell) mountPins(members map[nsKey][]member) []pin {
	var out []pin
	seen := map[string]bool{}
	var mnts []nsKey
	for k := range members {
		if k.typ == "mnt" {
			mnts = append(mnts, k)
		}
	}
	sort.Slice(mnts, func(i, j int) bool { return mnts[i].inum < mnts[j].inum })
	for _, k := range mnts {
		for _, m := range members[k] {
			b, err := fsutil.ReadFileNoAtime(filepath.Join(c.proc, strconv.Itoa(int(m.tgid)), "mountinfo"))
			if err != nil {
				continue // this process is gone or hidden: try another one of the namespace
			}
			for _, p := range parseNSFSMounts(string(b)) {
				id := p.key.String() + "|" + p.where
				if seen[id] {
					continue
				}
				seen[id] = true
				p.pid, p.comm = m.tgid, m.comm
				out = append(out, p)
			}
			break
		}
	}
	return out
}

// descriptorPins adds the descriptors that refer to a namespace file, as the
// kernel reports them from every task's file table. Unlike /proc/<pid>/fd, that
// includes processes hidden from /proc, and descriptors opened through a bind
// mount of the namespace file, whose link reads "/" instead of "net:[inum]".
// The descriptor is asked for its namespace type, so a descriptor of a hidden
// process is typed too.
func (c *Cell) descriptorPins(v *view, fds []fdowner.FD, rec *core.Recorder) {
	types := map[uint64]string{} // namespace inode -> type
	for k := range v.members {
		types[k.inum] = k.typ
	}
	for k := range v.pins {
		types[k.inum] = k.typ
	}
	untyped := 0
	for _, fd := range fds {
		if fd.TGID == 0 || fd.Inode == 0 {
			continue
		}
		typ, ok := types[fd.Inode]
		if !ok {
			var err error
			if typ, err = nsTypeOf(int(fd.TGID), int(fd.FD)); err != nil {
				// Older kernels have no pidfd_getfd: fall back to the descriptor's link.
				if t, ok := parseNSLink(readlinkFD(c.proc, fd.TGID, fd.FD)); ok {
					typ = t.typ
				} else {
					untyped++
					continue
				}
			}
			types[fd.Inode] = typ
		}
		key := nsKey{typ, fd.Inode}
		v.pins[key] = append(v.pins[key], pin{key: key, how: "descriptor", where: fmt.Sprintf("descriptor %d", fd.FD), pid: fd.TGID, comm: fd.Comm, fd: int(fd.FD)})
	}
	if untyped > 0 {
		rec.Limit("%d namespace descriptor(s) could not be typed (no pidfd_getfd, and the link of the descriptor is not readable): they were not checked", untyped)
	}
}

func readlinkFD(proc string, pid, fd uint32) string {
	s, _ := os.Readlink(filepath.Join(proc, strconv.Itoa(int(pid)), "fd", strconv.Itoa(int(fd))))
	return s
}

// ioctls on nsfs files (include/uapi/linux/nsfs.h).
const (
	nsGetUserNS = 0xb701 // the user namespace that owns this namespace (or the parent of a user namespace)
	nsGetParent = 0xb702 // the parent of a PID or user namespace
	nsGetType   = 0xb703 // the CLONE_NEW* flag of the namespace
)

// ownersOf returns the namespaces kept alive by the namespace file at path:
// its owning user namespace, and the ancestors of user and PID namespaces.
func ownersOf(path, typ string) []nsKey {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []nsKey
	var opened []int
	defer func() {
		for _, fd := range opened {
			unix.Close(fd)
		}
	}()
	// walk follows one ioctl up the hierarchy: owner of a namespace, then of that owner...
	walk := func(req uint, ownerType string) {
		cur := int(f.Fd())
		for depth := 0; depth < 32; depth++ {
			n, err := unix.IoctlRetInt(cur, req)
			if err != nil {
				return
			}
			opened = append(opened, n)
			var st unix.Stat_t
			if unix.Fstat(n, &st) != nil {
				return
			}
			out = append(out, nsKey{ownerType, st.Ino})
			cur = n
		}
	}
	walk(nsGetUserNS, "user")
	if typ == "pid" {
		walk(nsGetParent, "pid")
	}
	return out
}

// canary is a network namespace kept alive only by a socket of this process:
// the check has to report it as an orphan, or it would miss a rootkit's.
type canary struct {
	sock  int
	netns uint64
}

func newCanary() (*canary, error) {
	type result struct {
		sock  int
		netns uint64
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		// This thread joins a new network namespace and is never unlocked, so the
		// runtime ends it when the goroutine returns: no task stays in the namespace,
		// and the socket keeps it alive.
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			ch <- result{err: fmt.Errorf("unshare(CLONE_NEWNET): %w", err)}
			return
		}
		s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			ch <- result{err: err}
			return
		}
		ino, ok := nsInode("/proc/thread-self/ns/net")
		if !ok {
			unix.Close(s)
			ch <- result{err: fmt.Errorf("cannot read the canary namespace")}
			return
		}
		ch <- result{sock: s, netns: ino}
	}()
	r := <-ch
	if r.err != nil {
		return nil, r.err
	}
	// The thread ends shortly after it answered: wait until no task of this process is
	// still in the namespace, or the first reading would count it as a member.
	for i := 0; i < 100; i++ {
		if !taskInNetNS(r.netns) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return &canary{sock: r.sock, netns: r.netns}, nil
}

// taskInNetNS reports whether a thread of this process is in the network namespace.
func taskInNetNS(inum uint64) bool {
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return false
	}
	for _, t := range tasks {
		if ino, ok := nsInode("/proc/self/task/" + t.Name() + "/ns/net"); ok && ino == inum {
			return true
		}
	}
	return false
}

func (c *canary) Close() { unix.Close(c.sock) }
