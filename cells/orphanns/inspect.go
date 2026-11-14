package orphanns

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/fsutil"
)

// Looking inside an orphan namespace means running in it. That is done on a
// thread of its own that joins the namespace and never leaves: the thread is
// locked to its goroutine and never unlocked, so the runtime ends it when the
// goroutine returns, and no other thread of the scanner is ever affected. The
// thread only reads /proc files, which the kernel renders for the namespaces of
// the thread that reads them.

const (
	sioCGSKNS      = 0x894c // ioctl on a socket: a descriptor of its network namespace
	procSuperMagic = 0x9fa0
	enterTimeout   = 3 * time.Second
	maxProcRead    = 4 << 20
)

var errEnterTimeout = errors.New("timed out reading the namespace")

// enter runs fn on a fresh thread that has joined the namespace of nsFile.
func enter(nsFile *os.File, nstype int, fn func() (map[string]string, error)) (map[string]string, error) {
	type result struct {
		kv  map[string]string
		err error
	}
	ch := make(chan result, 1)
	fd := int(nsFile.Fd())
	go func() {
		runtime.LockOSThread() // never unlocked: the thread ends with this goroutine
		if nstype == unix.CLONE_NEWNS {
			// Threads share their root and working directory, and setns refuses a mount
			// namespace for a thread that does.
			if err := unix.Unshare(unix.CLONE_FS); err != nil {
				ch <- result{err: fmt.Errorf("unshare(CLONE_FS): %w", err)}
				return
			}
		}
		if err := unix.Setns(fd, nstype); err != nil {
			ch <- result{err: fmt.Errorf("setns: %w", err)}
			return
		}
		kv, err := fn()
		ch <- result{kv, err}
	}()
	select {
	case r := <-ch:
		return r.kv, r.err
	case <-time.After(enterTimeout):
		return nil, errEnterTimeout
	}
}

// readProc reads a /proc file in the namespaces of the calling thread.
func readProc(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := fsutil.ReadAll(f, maxProcRead)
	return string(b), err
}

// nsFileFor opens a namespace file of o: through its bind mount or a
// descriptor that refers to it, or for a network namespace held by a socket,
// through that socket. The inode is checked, so that a path or descriptor that
// changed meanwhile is not mistaken for the namespace.
func (c *Cell) nsFileFor(o *orphan) (*os.File, error) {
	var last error
	check := func(f *os.File) (*os.File, error) {
		var st unix.Stat_t
		if err := unix.Fstat(int(f.Fd()), &st); err != nil || st.Ino != o.key.inum {
			f.Close()
			return nil, errors.New("the namespace file changed")
		}
		return f, nil
	}
	for _, p := range o.pins {
		var path string
		switch p.how {
		case "bind mount":
			path = filepath.Join(c.proc, strconv.Itoa(int(p.pid)), "root", p.where)
		case "descriptor":
			path = filepath.Join(c.proc, strconv.Itoa(int(p.pid)), "fd", strconv.Itoa(p.fd))
		}
		f, err := os.Open(path)
		if err != nil {
			last = err
			continue
		}
		checked, err := check(f)
		if err == nil {
			return checked, nil
		}
		last = err
	}
	if o.key.typ == "net" {
		for _, s := range o.sockets {
			f, err := netnsOfSocket(int(s.TGID), int(s.FD))
			if err != nil {
				last = err
				continue
			}
			checked, err := check(f)
			if err == nil {
				return checked, nil
			}
			last = err
		}
	}
	if last == nil {
		last = errors.New("no path to the namespace")
	}
	return nil, last
}

// netnsOfSocket duplicates descriptor fd of process pid and asks it for its
// network namespace (Linux 5.6+ for pidfd_getfd).
func netnsOfSocket(pid, fd int) (*os.File, error) {
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, fmt.Errorf("pidfd_open: %w", err)
	}
	defer unix.Close(pidfd)
	sock, err := unix.PidfdGetfd(pidfd, fd, 0)
	if err != nil {
		return nil, fmt.Errorf("pidfd_getfd: %w", err)
	}
	defer unix.Close(sock)
	nsfd, err := unix.IoctlRetInt(sock, sioCGSKNS)
	if err != nil {
		return nil, fmt.Errorf("SIOCGSKNS: %w", err)
	}
	return os.NewFile(uintptr(nsfd), "netns"), nil
}

// contents describes what is inside an orphan namespace; notable is true
// when it holds something a leftover namespace does not (a device, a
// listener, a mount, shared memory).
type contents struct {
	kv      map[string]string
	notable bool
	err     error
}

// inspect enters o and describes it. hostMounts are the mounts of the host's
// mount namespace, to tell what the orphan adds.
func (c *Cell) inspect(o *orphan, hostMounts map[string]bool, hostHostname string) contents {
	var nstype int
	var fn func() (map[string]string, error)
	switch o.key.typ {
	case "net":
		nstype, fn = unix.CLONE_NEWNET, inspectNet
	case "mnt":
		nstype, fn = unix.CLONE_NEWNS, func() (map[string]string, error) { return inspectMnt(hostMounts) }
	case "ipc":
		nstype, fn = unix.CLONE_NEWIPC, inspectIPC
	case "uts":
		nstype, fn = unix.CLONE_NEWUTS, func() (map[string]string, error) { return inspectUTS(hostHostname) }
	default:
		return contents{err: fmt.Errorf("%s namespaces cannot be inspected without a process", o.key.typ)}
	}
	f, err := c.nsFileFor(o)
	if err != nil {
		return contents{err: err}
	}
	defer f.Close()
	kv, err := enter(f, nstype, fn)
	if err != nil {
		return contents{err: err}
	}
	notable := kv["notable"] != ""
	delete(kv, "notable")
	return contents{kv: kv, notable: notable}
}

func inspectNet() (map[string]string, error) {
	kv := map[string]string{}
	dev, err := readProc("/proc/thread-self/net/dev")
	if err != nil {
		return nil, err
	}
	var ifaces []string
	for i, line := range strings.Split(dev, "\n") {
		name, _, ok := strings.Cut(line, ":")
		if i < 2 || !ok {
			continue
		}
		ifaces = append(ifaces, strings.TrimSpace(name))
	}
	kv["interfaces"] = strings.Join(ifaces, ", ")
	for _, n := range ifaces {
		if n != "lo" {
			kv["notable"] = "yes"
		}
	}
	var listeners []string
	sockets := 0
	for _, t := range []struct {
		file, proto string
		v6          bool
	}{{"tcp", "tcp", false}, {"tcp6", "tcp", true}, {"udp", "udp", false}, {"udp6", "udp", true}, {"raw", "raw", false}, {"raw6", "raw", true}} {
		data, err := readProc("/proc/thread-self/net/" + t.file)
		if err != nil {
			continue
		}
		n, l := parseNetTable(data, t.proto, t.v6)
		sockets += n
		listeners = append(listeners, l...)
	}
	for _, file := range []string{"packet", "unix"} {
		if data, err := readProc("/proc/thread-self/net/" + file); err == nil {
			if rows := strings.Count(strings.TrimSpace(data), "\n"); rows > 0 {
				sockets += rows
				kv[file+"_sockets"] = strconv.Itoa(rows)
				if file == "packet" {
					kv["notable"] = "yes"
				}
			}
		}
	}
	sort.Strings(listeners)
	if len(listeners) > 0 {
		kv["listeners"] = strings.Join(listeners, ", ")
		kv["notable"] = "yes"
	}
	kv["sockets"] = strconv.Itoa(sockets)
	return kv, nil
}

// parseNetTable counts the sockets in a /proc/net/{tcp,udp,raw}[6] table and
// returns "proto addr:port" for the listening ones.
func parseNetTable(data, proto string, v6 bool) (sockets int, listeners []string) {
	for i, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 4 {
			continue
		}
		sockets++
		listening := (proto == "tcp" && f[3] == "0A") || (proto == "udp" && f[3] == "07")
		if !listening {
			continue
		}
		if addr, ok := parseProcAddr(f[1], v6); ok {
			listeners = append(listeners, proto+" "+addr)
		}
	}
	return sockets, listeners
}

// parseProcAddr decodes "0100007F:2328" (or the 32-digit IPv6 form) to "127.0.0.1:9000".
func parseProcAddr(s string, v6 bool) (string, bool) {
	host, port, ok := strings.Cut(s, ":")
	if !ok {
		return "", false
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return "", false
	}
	want := 8
	if v6 {
		want = 32
	}
	if len(host) != want {
		return "", false
	}
	raw := make([]byte, want/2)
	for i := 0; i < len(raw); i++ {
		b, err := strconv.ParseUint(host[2*i:2*i+2], 16, 8)
		if err != nil {
			return "", false
		}
		raw[i] = byte(b)
	}
	// The kernel prints each 32-bit word in host (little-endian) order.
	for w := 0; w+4 <= len(raw); w += 4 {
		raw[w], raw[w+1], raw[w+2], raw[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	return net.JoinHostPort(net.IP(raw).String(), strconv.FormatUint(p, 10)), true
}

// mountSig identifies a mount by what it is and where it is.
func mountSig(point, fstype, source string) string { return fstype + "|" + source + "|" + point }

// parseMountSigs returns the mounts of a mountinfo file as signatures, and a
// readable form of each.
func parseMountSigs(mountinfo string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(mountinfo, "\n") {
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
		point, fstype, source := unescapeOctal(f[4]), f[sep+1], unescapeOctal(f[sep+2])
		out[mountSig(point, fstype, source)] = fmt.Sprintf("%s %s on %s", fstype, source, point)
	}
	return out
}

func inspectMnt(host map[string]bool) (map[string]string, error) {
	var sfs unix.Statfs_t
	if err := unix.Statfs("/proc", &sfs); err != nil || sfs.Type != procSuperMagic {
		return nil, errors.New("no procfs at /proc in this mount namespace, so its mounts cannot be listed")
	}
	data, err := readProc("/proc/thread-self/mountinfo")
	if err != nil {
		return nil, err
	}
	mounts := parseMountSigs(data)
	var extra []string
	for sig, desc := range mounts {
		if !host[sig] {
			extra = append(extra, desc)
		}
	}
	sort.Strings(extra)
	kv := map[string]string{"mounts": strconv.Itoa(len(mounts))}
	if len(extra) > 0 {
		if len(extra) > 12 {
			extra = append(extra[:12], fmt.Sprintf("… (%d more)", len(extra)-12))
		}
		kv["mounts_the_host_does_not_have"] = strings.Join(extra, "; ")
		kv["notable"] = "yes"
	}
	return kv, nil
}

func inspectIPC() (map[string]string, error) {
	kv := map[string]string{}
	for _, f := range []string{"shm", "sem", "msg"} {
		data, err := readProc("/proc/sysvipc/" + f)
		if err != nil {
			continue
		}
		if rows := strings.Count(strings.TrimSpace(data), "\n"); rows > 0 {
			kv["sysv_"+f] = strconv.Itoa(rows)
			kv["notable"] = "yes"
		}
	}
	return kv, nil
}

func inspectUTS(host string) (map[string]string, error) {
	h, err := readProc("/proc/sys/kernel/hostname")
	if err != nil {
		return nil, err
	}
	h = strings.TrimSpace(h)
	kv := map[string]string{"hostname": h}
	if h != host {
		kv["notable"] = "yes"
	}
	return kv, nil
}
