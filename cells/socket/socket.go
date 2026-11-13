// Package socket detects TCP, UDP, RAW and AF_PACKET sockets hidden from
// userspace tools or held by hidden processes.
package socket

//go:generate go tool bpf2go -target amd64,arm64 -cflags "-Wall -Werror -Wno-missing-declarations" -type bpf_sock_rec socket socket.bpf.c -- -I../../bpf/include

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fdowner"
	"github.com/waldh4ri/zygarde/internal/fsutil"
	"github.com/waldh4ri/zygarde/internal/netlink"
)

// Cell compares TCP/UDP sockets across up to three views (BPF socket
// iterators, /proc/net and netlink sock_diag), confirms differences with a
// third read and exact sock_diag lookups, inventories AF_PACKET and SOCK_RAW
// sockets, and checks every socket FD in kernel task tables for hidden holders.
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
	return "Compares TCP/UDP sockets across BPF iterators, /proc/net (netstat) and netlink sock_diag (ss), audits AF_PACKET/RAW sockets, and flags sockets held by hidden processes"
}

type view map[key]sock

type sources struct {
	proc, diag, bpf view
	haveBPF         bool
	compared        map[string]bool
}

func family(s sock) string { return s.Proto + strconv.Itoa(s.Family) }

func (c *Cell) Run(ctx context.Context, env *core.Env, rec *core.Recorder) error {
	selfNetNS, initNetNS, netnsErr := netns()
	if netnsErr == nil && selfNetNS != initNetNS {
		rec.Limit("zygarde runs in its own network namespace, so only that namespace's /proc/net and netlink tables were checked")
	}

	cs, err := openCanaries(rec)
	if err != nil {
		return fmt.Errorf("opening canary sockets: %w", err)
	}
	defer cs.Close()

	bpfObjs := loadSocketIterators(env, rec)
	if bpfObjs != nil {
		defer bpfObjs.Close()
	}

	first, err := c.snapshot(rec, bpfObjs)
	if err != nil {
		return err
	}
	onlyProc, onlyDiag, onlyBPF := compare(first)
	if len(onlyProc)+len(onlyDiag)+len(onlyBPF) > 0 {
		second, err := c.snapshot(nil, bpfObjs)
		if err != nil {
			return err
		}
		p2, d2, b2 := compare(second)
		onlyProc = intersect(onlyProc, p2)
		onlyDiag = intersect(onlyDiag, d2)
		onlyBPF = intersect(onlyBPF, b2)
	}
	if len(onlyProc)+len(onlyDiag) > 0 {
		onlyProc, onlyDiag = c.confirm(onlyProc, onlyDiag, bpfObjs)
	}

	for _, cn := range cs.socks {
		k := key{cn.proto, cn.inode}
		_, inProc := first.proc[k]
		_, inDiag := first.diag[k]
		rec.Canary(cn.label, "/proc/net (netstat)", inProc)
		if first.compared[cn.proto+"4"] {
			rec.Canary(cn.label, "netlink sock_diag (ss)", inDiag)
		}
		if first.haveBPF {
			_, inBPF := first.bpf[k]
			rec.Canary(cn.label, "BPF socket iterator", inBPF)
		}
	}

	table, listed := owners(env, rec)
	heldBy := func(ino uint64) []fdowner.Holder {
		if table == nil {
			return nil
		}
		return table.Holders(fdowner.Socket, ino)
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
			Details:     details(s, heldBy(s.Inode)),
			Why: "ss lists sockets over netlink and netstat reads /proc/net; both report the same kernel tables. " +
				"A socket missing from one of them is being filtered, typically to hide a backdoor's listener or connection.",
			Benign: "None expected: the difference was seen in three reads of both views.",
		})
	}
	for _, s := range onlyDiag {
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("Socket %s is visible to ss (netlink) but hidden from /proc/net (netstat)", s),
			Details:     details(s, heldBy(s.Inode)),
			Why: "netstat reads /proc/net and ss uses netlink; both report the same kernel tables. Rootkits commonly " +
				"hook the /proc/net show functions (tcp4_seq_show...) to hide their listener from netstat.",
			Benign: "None expected: the difference was seen in three reads of both views.",
		})
	}
	for _, s := range onlyBPF {
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("Socket %s exists in kernel hash tables (BPF iterator) but is hidden from both /proc/net and ss", s),
			Details:     details(s, heldBy(s.Inode)),
			Why: "The BPF socket iterator walked the kernel's TCP/UDP tables directly and found this socket, while " +
				"both /proc/net and netlink sock_diag omitted it across two snapshots.",
			Benign: "None expected: the socket persisted across two snapshots.",
		})
	}

	rawHidden, sniffers := c.checkPacketAndRaw(rec, table, selfNetNS, netnsErr == nil)

	all := map[key]sock{}
	for _, v := range []view{first.proc, first.diag, first.bpf} {
		for k, s := range v {
			all[k] = s
		}
	}
	keys := make([]key, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Inode < keys[j].Inode })

	reportedInodes := map[uint64]bool{}
	hiddenOwner := 0
	for _, k := range keys {
		s := all[k]
		if table == nil || cs.has(k) {
			continue
		}
		holders := heldBy(s.Inode)
		switch {
		case listed != nil && fdowner.HiddenOnly(holders, listed) && fdowner.StillHidden(holders):
			hiddenOwner++
			reportedInodes[s.Inode] = true
			rec.Suspicious(core.Finding{
				Description: fmt.Sprintf("Socket %s is held only by process(es) hidden from /proc: %s", s, fdowner.Describe(holders)),
				Details:     details(s, holders),
				Why: "The kernel's file tables show which processes hold this socket, and none of them is listed in " +
					"/proc. A hidden process with a listener or an open connection is the usual shape of a backdoor.",
				Benign: "None expected: the holders were read from the kernel's task list, which /proc normally mirrors.",
			})
		case len(holders) == 0 && (s.State == 10 || s.State == 1 || s.Proto == "udp"):
			rec.Observe(fmt.Sprintf("Socket %s is held by no process", s), details(s, nil))
		}
	}

	if table != nil && listed != nil {
		seenIno := map[uint64]fdowner.FD{}
		for _, f := range table.Of(fdowner.Socket) {
			if f.Inode != 0 && !reportedInodes[f.Inode] && !cs.hasInode(f.Inode) {
				seenIno[f.Inode] = f
			}
		}
		var extraInos []uint64
		for ino := range seenIno {
			extraInos = append(extraInos, ino)
		}
		sort.Slice(extraInos, func(i, j int) bool { return extraInos[i] < extraInos[j] })
		for _, ino := range extraInos {
			holders := heldBy(ino)
			if fdowner.HiddenOnly(holders, listed) && fdowner.StillHidden(holders) {
				hiddenOwner++
				fd := seenIno[ino]
				fam := sockFamilyName(fd.SockFamily)
				rec.Suspicious(core.Finding{
					Description: fmt.Sprintf("Socket inode %d (%s) is held only by process(es) hidden from /proc: %s", ino, fam, fdowner.Describe(holders)),
					Details: map[string]string{
						"inode":       strconv.FormatUint(ino, 10),
						"family":      fam,
						"socket_type": strconv.Itoa(int(fd.SockType)),
						"held_by":     fdowner.Describe(holders),
					},
					Why: "Every process holding this socket descriptor in the kernel's task table is hidden from /proc, " +
						"even though the socket was not listed in /proc/net TCP/UDP tables (e.g. raw/packet/unix or a separate netns).",
					Benign: "None expected.",
				})
			}
		}
	}

	totalSusp := len(onlyProc) + len(onlyDiag) + len(onlyBPF) + hiddenOwner + rawHidden
	switch {
	case totalSusp > 0 && sniffers > 0:
		rec.Message("%d hidden socket(s) and %d unrecognised packet sniffer(s)", totalSusp, sniffers)
	case totalSusp > 0:
		rec.Message("%d hidden socket(s) (/proc/net: %d, netlink: %d)", totalSusp, len(first.proc), len(first.diag))
	case sniffers > 0:
		rec.Message("%d unrecognised packet sniffer(s); /proc/net and netlink agree on %d sockets", sniffers, len(first.proc))
	case len(first.compared) == 0:
		rec.Message("%d sockets in /proc/net; netlink sock_diag is unavailable, so only their owners were checked", len(first.proc))
	default:
		rec.Message("/proc/net and netlink agree on %d sockets", len(first.proc))
	}
	return nil
}

// confirm re-checks sockets missing from one view with a third read of both
// views and an exact (non-dump) sock_diag lookup by addresses and ports.
func (c *Cell) confirm(onlyProc, onlyDiag []sock, bpfObjs *socketObjects) ([]sock, []sock) {
	third, err := c.snapshot(nil, bpfObjs)
	if err != nil {
		return onlyProc, onlyDiag
	}
	var p, d []sock
	for _, s := range onlyProc {
		_, inProc := third.proc[s.key()]
		_, inDiag := third.diag[s.key()]
		if !inProc || inDiag {
			continue
		}
		p = append(p, s)
	}
	for _, s := range onlyDiag {
		if _, inProc := third.proc[s.key()]; inProc {
			continue
		}
		if found, err := diagLookup(s); err == nil && !found {
			continue
		}
		d = append(d, s)
	}
	return p, d
}

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

// checkPacketAndRaw inventories AF_PACKET and RAW sockets and returns the
// number of packet sockets hidden from /proc/net/packet and of unrecognised
// packet sniffers.
func (c *Cell) checkPacketAndRaw(rec *core.Recorder, table *fdowner.Table, selfNetNS uint64, haveNetNS bool) (int, int) {
	pktSocks := c.readPacketSocks()
	rawSocks := c.readRawSocks()
	sniffers := c.checkSniffers(rec, table, pktSocks) + c.checkRawSockets(rec, table, append([]sock(nil), rawSocks...))

	heldBy := func(ino uint64) string {
		if table == nil {
			return ""
		}
		return fdowner.Describe(table.Holders(fdowner.Socket, ino))
	}

	pktInodes := map[uint64]bool{}
	for _, p := range pktSocks {
		pktInodes[p.Inode] = true
		d := map[string]string{
			"protocol": fmt.Sprintf("0x%04x", p.Proto),
			"ifindex":  strconv.Itoa(p.Ifindex),
			"uid":      strconv.FormatUint(uint64(p.UID), 10),
			"inode":    strconv.FormatUint(p.Inode, 10),
		}
		if h := heldBy(p.Inode); h != "" {
			d["held_by"] = h
		}
		rec.Observe(fmt.Sprintf("AF_PACKET socket (proto 0x%04x, ifindex %d, inode %d)", p.Proto, p.Ifindex, p.Inode), d)
	}

	for _, r := range rawSocks {
		var holders []fdowner.Holder
		if table != nil {
			holders = table.Holders(fdowner.Socket, r.Inode)
		}
		rec.Observe(fmt.Sprintf("RAW%d socket %s (inode %d)", r.Family, r.Local, r.Inode), details(r, holders))
	}

	if table == nil || !haveNetNS {
		return 0, sniffers
	}
	if _, err := os.Stat(c.procNet + "/packet"); err != nil {
		return 0, sniffers
	}
	suspicious := 0
	seen := map[uint64]bool{}
	for _, f := range table.Of(fdowner.Socket) {
		if f.SockFamily != unix.AF_PACKET || f.Inode == 0 || pktInodes[f.Inode] || seen[f.Inode] {
			continue
		}
		if procNetNS, err := pidNetNS(f.TGID); err != nil || procNetNS != selfNetNS {
			continue
		}
		seen[f.Inode] = true
		fresh := c.readPacketSocks()
		found := false
		for _, p := range fresh {
			if p.Inode == f.Inode {
				found = true
				break
			}
		}
		if found || errors.Is(unix.Kill(int(f.TGID), 0), unix.ESRCH) {
			continue
		}
		suspicious++
		holders := table.Holders(fdowner.Socket, f.Inode)
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("AF_PACKET socket (inode %d) held by %s is hidden from /proc/net/packet", f.Inode, fdowner.Describe(holders)),
			Details: map[string]string{
				"inode":   strconv.FormatUint(f.Inode, 10),
				"family":  "AF_PACKET",
				"held_by": fdowner.Describe(holders),
			},
			Why: "AF_PACKET raw sockets receive raw frames before firewall rules, how passive backdoors (e.g. BPFDoor) " +
				"listen for magic packets without opening a port. Hiding the socket from /proc/net/packet conceals the sniffer.",
			Benign: "None expected: the socket descriptor is open in the same network namespace across two checks.",
		})
	}
	return suspicious, sniffers
}

func (c *Cell) readPacketSocks() []packetSock {
	var out []packetSock
	_ = fsutil.WithComm("netstat", func() error {
		f, err := fsutil.OpenNoAtime(c.procNet + "/packet")
		if err != nil {
			return err
		}
		defer f.Close()
		out, _ = parseProcPacket(f)
		return nil
	})
	return out
}

func (c *Cell) readRawSocks() []sock {
	var out []sock
	_ = fsutil.WithComm("netstat", func() error {
		for _, item := range []struct {
			file  string
			ipver int
		}{{"raw", 4}, {"raw6", 6}} {
			f, err := fsutil.OpenNoAtime(c.procNet + "/" + item.file)
			if err != nil {
				continue
			}
			socks, err := parseProcNet(f, "raw", item.ipver)
			f.Close()
			if err == nil {
				for _, s := range socks {
					if s.Inode != 0 {
						out = append(out, s)
					}
				}
			}
		}
		return nil
	})
	return out
}

func sockFamilyName(fam uint16) string {
	switch fam {
	case unix.AF_UNIX:
		return "AF_UNIX"
	case unix.AF_INET:
		return "AF_INET"
	case unix.AF_INET6:
		return "AF_INET6"
	case unix.AF_NETLINK:
		return "AF_NETLINK"
	case unix.AF_PACKET:
		return "AF_PACKET"
	case unix.AF_VSOCK:
		return "AF_VSOCK"
	default:
		return fmt.Sprintf("AF_%d", fam)
	}
}

func pidNetNS(pid uint32) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(fmt.Sprintf("/proc/%d/ns/net", pid), &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

func loadSocketIterators(env *core.Env, rec *core.Recorder) *socketObjects {
	if env == nil || env.BTF == nil || env.Lockdown == "confidentiality" {
		return nil
	}
	if _, err := env.BTF.AnyTypeByName("bpf_iter__tcp"); err != nil {
		return nil
	}
	if _, err := env.BTF.AnyTypeByName("bpf_iter__udp"); err != nil {
		return nil
	}
	spec, err := loadSocket()
	if err != nil {
		return nil
	}
	var objs socketObjects
	if err := bpfutil.Load(env, spec, &objs); err != nil {
		rec.Log().Debug("BPF socket iterators unavailable", "err", err)
		return nil
	}
	for _, p := range []*ebpf.Program{objs.DumpTcp, objs.DumpUdp} {
		if id, err := bpfutil.ProgramID(p); err == nil {
			rec.Footprint("bpf_prog_id", strconv.FormatUint(uint64(id), 10))
		}
	}
	return &objs
}

func readBPFSockets(objs *socketObjects) (view, bool) {
	out := view{}
	if objs == nil {
		return out, false
	}
	for _, prog := range []*ebpf.Program{objs.DumpTcp, objs.DumpUdp} {
		data, err := bpfutil.ReadIter(prog)
		if err != nil {
			return view{}, false
		}
		recs, err := bpfutil.Decode[socketBpfSockRec](data)
		if err != nil {
			return view{}, false
		}
		for _, r := range recs {
			if r.Ino == 0 {
				continue
			}
			proto := "tcp"
			if r.Proto == 2 {
				proto = "udp"
			}
			alen := 4
			if r.Family == 6 {
				alen = 16
			}
			src, _ := netip.AddrFromSlice(r.Src[:alen])
			dst, _ := netip.AddrFromSlice(r.Dst[:alen])
			s := sock{
				Proto:  proto,
				Family: int(r.Family),
				Local:  netip.AddrPortFrom(src, r.Sport),
				Remote: netip.AddrPortFrom(dst, r.Dport),
				State:  r.State,
				UID:    r.Uid,
				Inode:  r.Ino,
			}
			out[s.key()] = s
		}
	}
	return out, true
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

func (c *Cell) snapshot(rec *core.Recorder, bpfObjs *socketObjects) (sources, error) {
	s := sources{proc: view{}, diag: view{}, bpf: view{}, compared: map[string]bool{}}
	var unsupported []string
	defer func() {
		if rec != nil && len(unsupported) > 0 {
			rec.Limit("%s sockets not compared with netlink: the kernel has no sock_diag support for them (CONFIG_INET_DIAG)", strings.Join(unsupported, ", "))
		}
	}()
	if bpfObjs != nil {
		s.bpf, s.haveBPF = readBPFSockets(bpfObjs)
	}
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
		missing := false
		var pSocks []sock
		err := fsutil.WithComm("netstat", func() error {
			f, oerr := fsutil.OpenNoAtime(c.procNet + "/" + src.file)
			if errors.Is(oerr, os.ErrNotExist) {
				missing = true
				return nil
			}
			if oerr != nil {
				return oerr
			}
			defer f.Close()
			var perr error
			pSocks, perr = parseProcNet(f, src.proto, src.ipver)
			if perr != nil {
				return fmt.Errorf("parsing %s/%s: %w", c.procNet, src.file, perr)
			}
			return nil
		})
		if err != nil {
			return s, err
		}
		if missing {
			continue
		}

		for _, p := range pSocks {
			if p.Inode != 0 {
				s.proc[p.key()] = p
			}
		}

		msgs, err := fsutil.WithCommVal("ss", func() ([]netlink.Message, error) {
			return netlink.Dump(unix.NETLINK_SOCK_DIAG, unix.SOCK_DIAG_BY_FAMILY, diagRequest(uint8(src.family), src.protocol))
		})
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

func compare(s sources) (onlyProc, onlyDiag, onlyBPF []sock) {
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
	if s.haveBPF {
		for k, b := range s.bpf {
			_, inProc := s.proc[k]
			_, inDiag := s.diag[k]
			if !inProc && (!s.compared[family(b)] || !inDiag) {
				onlyBPF = append(onlyBPF, b)
			}
		}
	}
	sort.Slice(onlyProc, func(i, j int) bool { return onlyProc[i].Inode < onlyProc[j].Inode })
	sort.Slice(onlyDiag, func(i, j int) bool { return onlyDiag[i].Inode < onlyDiag[j].Inode })
	sort.Slice(onlyBPF, func(i, j int) bool { return onlyBPF[i].Inode < onlyBPF[j].Inode })
	return onlyProc, onlyDiag, onlyBPF
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

type canaries struct {
	closers []interface{ Close() error }
	socks   []canarySock
}

type canarySock struct {
	label string
	proto string
	inode uint64
}

func openCanaries(rec *core.Recorder) (*canaries, error) {
	cs := &canaries{}
	loopback := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
	ln, err := net.ListenTCP("tcp4", loopback)
	if err != nil {
		return nil, err
	}
	cs.closers = append(cs.closers, ln)
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback.IP})
	if err != nil {
		cs.Close()
		return nil, err
	}
	cs.closers = append(cs.closers, pc)

	for _, c := range []struct {
		conn  syscall.Conn
		proto string
		addr  net.Addr
	}{{ln, "tcp", ln.Addr()}, {pc, "udp", pc.LocalAddr()}} {
		ino, err := inode(c.conn)
		if err != nil {
			cs.Close()
			return nil, err
		}
		label := fmt.Sprintf("%s socket %s", c.proto, c.addr)
		cs.socks = append(cs.socks, canarySock{label: label, proto: c.proto, inode: ino})
		if rec != nil {
			rec.Footprint("canary_socket", fmt.Sprintf("%s (inode %d)", label, ino))
		}
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

func (cs *canaries) hasInode(ino uint64) bool {
	for _, s := range cs.socks {
		if s.inode == ino {
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
