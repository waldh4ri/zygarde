// Package socket detects TCP and UDP sockets hidden from one of the two
// interfaces userspace tools list them with.
package socket

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fdowner"
	"github.com/waldh4ri/zygarde/internal/netlink"
)

// Cell compares the sockets listed in /proc/net/{tcp,udp}{,6}, which netstat
// reads, with those reported over netlink sock_diag, which ss uses. The two
// are separate code paths in the kernel, and rootkits usually filter only
// one: hooking the seq_file show functions (tcp4_seq_show...) or the netlink
// reply.
//
// It also attributes each socket to the processes holding it, read from the
// kernel's file tables: a socket held only by a process hidden from /proc
// belongs to a hidden backdoor.
//
// Only zygarde's own network namespace is checked.
type Cell struct {
	procNet string
}

// New returns the hidden socket Cell.
func New() *Cell { return &Cell{procNet: "/proc/net"} }

func (*Cell) ID() string                    { return "hidden_socket" }
func (*Cell) Name() string                  { return "Hidden Socket Detection" }
func (*Cell) Timeout() time.Duration        { return 30 * time.Second }
func (*Cell) Supported(env *core.Env) error { return nil }
func (*Cell) Description() string {
	return "Compares TCP/UDP sockets in /proc/net (netstat) with netlink sock_diag (ss), and flags sockets held only by hidden processes"
}

// view is one source's sockets, by key.
type view map[key]sock

type sources struct {
	proc, diag view
	// compared lists the families netlink reported ("tcp4", "udp6"...).
	// Only those are compared; /proc/net is read for all of them.
	compared map[string]bool
}

func family(s sock) string { return s.Proto + strconv.Itoa(s.Family) }

func (c *Cell) Run(ctx context.Context, env *core.Env, rec *core.Recorder) error {
	if self, init, err := netns(); err == nil && self != init {
		rec.Limit("zygarde runs in its own network namespace, so only that namespace's sockets were checked")
	}

	cs, err := openCanaries()
	if err != nil {
		return fmt.Errorf("opening canary sockets: %w", err)
	}
	defer cs.Close()

	first, err := c.snapshot(rec)
	if err != nil {
		return err
	}
	onlyProc, onlyDiag := compare(first)
	// Sockets open and close all the time: keep only differences seen in
	// two snapshots, for sockets that still exist.
	if len(onlyProc)+len(onlyDiag) > 0 {
		second, err := c.snapshot(nil)
		if err != nil {
			return err
		}
		p2, d2 := compare(second)
		onlyProc, onlyDiag = intersect(onlyProc, p2), intersect(onlyDiag, d2)
	}
	// Dumps resume at a (bucket, index) position, so heavy churn can make
	// both skip a stable socket twice. Confirm what is left directly.
	if len(onlyProc)+len(onlyDiag) > 0 {
		onlyProc, onlyDiag = c.confirm(onlyProc, onlyDiag)
	}

	for _, cn := range cs.socks {
		k := key{cn.proto, cn.inode}
		_, inProc := first.proc[k]
		_, inDiag := first.diag[k]
		rec.Canary(cn.label, "/proc/net (netstat)", inProc)
		if first.compared[cn.proto+"4"] {
			rec.Canary(cn.label, "netlink sock_diag (ss)", inDiag)
		}
	}

	table, listed := owners(env, rec)
	heldBy := func(s sock) []fdowner.Holder {
		if table == nil {
			return nil
		}
		return table.Holders(fdowner.Socket, s.Inode)
	}
	if table != nil {
		self := uint32(os.Getpid())
		for _, cn := range cs.socks {
			held := false
			for _, h := range table.Holders(fdowner.Socket, cn.inode) {
				held = held || h.TGID == self
			}
			rec.Canary(cn.label+" held by zygarde", "process file tables (task_file iterator)", held)
		}
	}

	for _, s := range onlyProc {
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("Socket %s is listed in /proc/net but hidden from netlink sock_diag (ss)", s),
			Details:     details(s, heldBy(s)),
			Why: "ss lists sockets over netlink and netstat reads /proc/net; both report the same kernel tables. " +
				"A socket missing from one of them is being filtered, typically to hide a backdoor's listener or connection.",
			Benign: "None expected: the difference was seen in two snapshots.",
		})
	}
	for _, s := range onlyDiag {
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("Socket %s is visible to ss (netlink) but hidden from /proc/net (netstat)", s),
			Details:     details(s, heldBy(s)),
			Why: "netstat reads /proc/net and ss uses netlink; both report the same kernel tables. Rootkits commonly " +
				"hook the /proc/net show functions (tcp4_seq_show...) to hide their listener from netstat.",
			Benign: "None expected: the difference was seen in two snapshots.",
		})
	}

	// Ownership of every socket either view reports.
	all := map[key]sock{}
	for k, s := range first.proc {
		all[k] = s
	}
	for k, s := range first.diag {
		all[k] = s
	}
	keys := make([]key, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Inode < keys[j].Inode })
	hiddenOwner := 0
	for _, k := range keys {
		s := all[k]
		if table == nil || cs.has(k) {
			continue
		}
		holders := heldBy(s)
		switch {
		case listed != nil && fdowner.HiddenOnly(holders, listed) && fdowner.StillHidden(holders):
			hiddenOwner++
			rec.Suspicious(core.Finding{
				Description: fmt.Sprintf("Socket %s is held only by process(es) hidden from /proc: %s", s, fdowner.Describe(holders)),
				Details:     details(s, holders),
				Why: "The kernel's file tables show which processes hold this socket, and none of them is listed in " +
					"/proc. A hidden process with a listener or an open connection is the usual shape of a backdoor.",
				Benign: "None expected: the holders were read from the kernel's task list, which /proc normally mirrors.",
			})
		case len(holders) == 0 && (s.State == 10 || s.State == 1 || s.Proto == "udp"):
			// Kernel sockets (NFS, WireGuard, VXLAN...) have no holder.
			rec.Observe(fmt.Sprintf("Socket %s is held by no process", s), details(s, nil))
		}
	}

	switch n := len(onlyProc) + len(onlyDiag) + hiddenOwner; {
	case n > 0:
		rec.Message("%d hidden socket(s) (/proc/net: %d, netlink: %d)", n, len(first.proc), len(first.diag))
	case len(first.compared) == 0:
		rec.Message("%d sockets in /proc/net; netlink sock_diag is unavailable, so only their owners were checked", len(first.proc))
	default:
		rec.Message("/proc/net and netlink agree on %d sockets", len(first.proc))
	}
	return nil
}

func details(s sock, holders []fdowner.Holder) map[string]string {
	d := map[string]string{
		"protocol": s.Proto + strconv.Itoa(s.Family),
		"local":    s.Local.String(),
		"remote":   s.Remote.String(),
		"state":    stateName(s.Proto, s.State),
		"inode":    strconv.FormatUint(s.Inode, 10),
		"uid":      strconv.FormatUint(uint64(s.UID), 10),
	}
	if len(holders) > 0 {
		d["held_by"] = fdowner.Describe(holders)
	}
	return d
}

// snapshot reads both views back to back. Families or protocols the kernel
// lacks are recorded as limitations (rec may be nil on re-checks).
func (c *Cell) snapshot(rec *core.Recorder) (sources, error) {
	s := sources{proc: view{}, diag: view{}, compared: map[string]bool{}}
	var unsupported []string
	defer func() {
		if rec != nil && len(unsupported) > 0 {
			rec.Limit("%s sockets not compared with netlink: the kernel has no sock_diag support for them (CONFIG_INET_DIAG)", strings.Join(unsupported, ", "))
		}
	}()
	for _, src := range []struct {
		file          string
		proto         string
		family, ipver int
		protocol      uint8
	}{
		{"tcp", "tcp", unix.AF_INET, 4, unix.IPPROTO_TCP},
		{"tcp6", "tcp", unix.AF_INET6, 6, unix.IPPROTO_TCP},
		{"udp", "udp", unix.AF_INET, 4, unix.IPPROTO_UDP},
		{"udp6", "udp", unix.AF_INET6, 6, unix.IPPROTO_UDP},
	} {
		f, err := os.Open(c.procNet + "/" + src.file)
		if errors.Is(err, os.ErrNotExist) {
			continue // e.g. IPv6 disabled
		}
		if err != nil {
			return s, err
		}
		procSocks, err := parseProcNet(f, src.proto, src.ipver)
		f.Close()
		if err != nil {
			return s, fmt.Errorf("parsing %s/%s: %w", c.procNet, src.file, err)
		}

		for _, p := range procSocks {
			if p.Inode != 0 {
				s.proc[p.key()] = p
			}
		}

		msgs, err := netlink.Dump(unix.NETLINK_SOCK_DIAG, unix.SOCK_DIAG_BY_FAMILY, diagRequest(uint8(src.family), src.protocol))
		if err != nil {
			if netlink.ErrUnsupported(err) {
				unsupported = append(unsupported, src.file)
				continue
			}
			return s, fmt.Errorf("sock_diag %s: %w", src.file, err)
		}
		s.compared[src.proto+strconv.Itoa(src.ipver)] = true
		for _, m := range msgs {
			if d, ok := parseDiagMsg(m.Data, src.proto); ok && d.Inode != 0 {
				s.diag[d.key()] = d
			}
		}
	}
	return s, nil
}

// confirm re-checks sockets missing from one view with a third read of both
// views and an exact (non-dump) sock_diag lookup by addresses and ports,
// which goes straight to the kernel's hash tables. A socket stays a finding
// only if the third read still misses it in the same view, and it still
// exists: listed in the other view for /proc/net-only sockets, found by the
// exact lookup for netlink-only ones. An exact lookup that finds a socket the
// dumps keep missing doesn't clear it: hiding from dumps is what a filter on
// ss's path does.
func (c *Cell) confirm(onlyProc, onlyDiag []sock) ([]sock, []sock) {
	third, err := c.snapshot(nil)
	if err != nil {
		return onlyProc, onlyDiag
	}
	var p, d []sock
	for _, s := range onlyProc {
		_, inProc := third.proc[s.key()]
		_, inDiag := third.diag[s.key()]
		if !inProc || inDiag {
			continue // closed, or the dump caught up
		}
		p = append(p, s)
	}
	for _, s := range onlyDiag {
		if _, inProc := third.proc[s.key()]; inProc {
			continue
		}
		if found, err := diagLookup(s); err == nil && !found {
			continue // closed meanwhile
		}
		d = append(d, s)
	}
	return p, d
}

// diagLookup asks sock_diag for one socket by its addresses and ports and
// reports whether the socket it finds has the same inode.
func diagLookup(s sock) (bool, error) {
	m, err := netlink.Get(unix.NETLINK_SOCK_DIAG, unix.SOCK_DIAG_BY_FAMILY, diagExactRequest(s))
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	got, ok := parseDiagMsg(m.Data, s.Proto)
	return ok && got.Inode == s.Inode, nil
}

// compare returns sockets present in only one view.
func compare(s sources) (onlyProc, onlyDiag []sock) {
	for k, p := range s.proc {
		if _, ok := s.diag[k]; !ok && s.compared[family(p)] {
			onlyProc = append(onlyProc, p)
		}
	}
	for k, d := range s.diag {
		if _, ok := s.proc[k]; !ok {
			onlyDiag = append(onlyDiag, d)
		}
	}
	sort.Slice(onlyProc, func(i, j int) bool { return onlyProc[i].Inode < onlyProc[j].Inode })
	sort.Slice(onlyDiag, func(i, j int) bool { return onlyDiag[i].Inode < onlyDiag[j].Inode })
	return onlyProc, onlyDiag
}

func intersect(a, b []sock) []sock {
	in := map[key]bool{}
	for _, s := range b {
		in[s.key()] = true
	}
	var out []sock
	for _, s := range a {
		if in[s.key()] {
			out = append(out, s)
		}
	}
	return out
}

// owners reads socket ownership from the kernel, and the PIDs /proc lists.
// Either may be nil when it can't be determined here.
func owners(env *core.Env, rec *core.Recorder) (*fdowner.Table, map[uint32]bool) {
	if err := fdowner.Supported(env); err != nil {
		rec.Limit("Socket owners not identified: %v", err)
		return nil, nil
	}
	table, err := fdowner.Snapshot(env)
	if err != nil {
		rec.Limit("Socket owners not identified: %v", err)
		return nil, nil
	}
	if !table.Learned[fdowner.Socket] {
		rec.Limit("Socket owners not identified: zygarde could not open a socket to learn from")
		return nil, nil
	}
	if self, err := os.Readlink("/proc/self"); err != nil || self != strconv.Itoa(os.Getpid()) {
		rec.Limit("Socket owners not compared with /proc: /proc belongs to another PID namespace")
		return table, nil
	}
	listed, err := fdowner.ListedPIDs()
	if err != nil {
		rec.Limit("Socket owners not compared with /proc: %v", err)
		return table, nil
	}
	return table, listed
}

// netns returns the network namespace inodes of zygarde and of PID 1.
func netns() (self, init uint64, err error) {
	var a, b unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &a); err != nil {
		return 0, 0, err
	}
	if err := unix.Stat("/proc/1/ns/net", &b); err != nil {
		return 0, 0, err
	}
	return a.Ino, b.Ino, nil
}

// canaries are sockets zygarde opens itself, which both views must list.
type canaries struct {
	closers []interface{ Close() error }
	socks   []canarySock
}

type canarySock struct {
	label string
	proto string
	inode uint64
}

func openCanaries() (*canaries, error) {
	cs := &canaries{}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	cs.closers = append(cs.closers, ln)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		cs.Close()
		return nil, err
	}
	cs.closers = append(cs.closers, pc)

	for _, c := range []struct {
		conn  syscall.Conn
		proto string
		addr  net.Addr
	}{{ln.(*net.TCPListener), "tcp", ln.Addr()}, {pc.(*net.UDPConn), "udp", pc.LocalAddr()}} {
		ino, err := inode(c.conn)
		if err != nil {
			cs.Close()
			return nil, err
		}
		cs.socks = append(cs.socks, canarySock{label: fmt.Sprintf("%s socket %s", c.proto, c.addr), proto: c.proto, inode: ino})
	}
	return cs, nil
}

func (cs *canaries) has(k key) bool {
	for _, s := range cs.socks {
		if s.proto == k.Proto && s.inode == k.Inode {
			return true
		}
	}
	return false
}

func (cs *canaries) Close() {
	for _, c := range cs.closers {
		c.Close()
	}
}

func inode(c syscall.Conn) (uint64, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var st unix.Stat_t
	var serr error
	if err := raw.Control(func(fd uintptr) { serr = unix.Fstat(int(fd), &st) }); err != nil {
		return 0, err
	}
	return st.Ino, serr
}
