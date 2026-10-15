package socket

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// sock is one TCP or UDP socket as one view reports it.
type sock struct {
	Proto  string // "tcp" or "udp"
	Family int    // 4 or 6
	Local  netip.AddrPort
	Remote netip.AddrPort
	State  uint8
	UID    uint32
	Inode  uint64
}

// key identifies a socket across views. Sockets without an inode (TIME_WAIT,
// orphans, request sockets) are not tracked.
type key struct {
	Proto string
	Inode uint64
}

func (s sock) key() key { return key{s.Proto, s.Inode} }

func (s sock) String() string {
	state := stateName(s.Proto, s.State)
	if s.Remote.Port() == 0 && s.Remote.Addr().IsUnspecified() {
		return fmt.Sprintf("%s%d %s (%s)", strings.ToUpper(s.Proto), s.Family, s.Local, state)
	}
	return fmt.Sprintf("%s%d %s -> %s (%s)", strings.ToUpper(s.Proto), s.Family, s.Local, s.Remote, state)
}

// stateName names a TCP state (include/net/tcp_states.h). UDP reuses the
// values: 1 for connected sockets, 7 for unconnected ones.
func stateName(proto string, st uint8) string {
	if proto == "udp" {
		if st == 1 {
			return "connected"
		}
		return "unconnected"
	}
	names := []string{"", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT",
		"CLOSE", "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING", "NEW_SYN_RECV"}
	if int(st) < len(names) && names[st] != "" {
		return names[st]
	}
	return "state " + strconv.Itoa(int(st))
}

// parseProcNet parses /proc/net/{tcp,udp}{,6}:
//
//	sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
//	0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 ...
//
// Addresses are the kernel's in-memory words printed as native integers.
func parseProcNet(r io.Reader, proto string, family int) ([]sock, error) {
	var out []sock
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue // header
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		local, err := parseHexAddr(f[1])
		if err != nil {
			return out, err
		}
		remote, err := parseHexAddr(f[2])
		if err != nil {
			return out, err
		}
		st, err := strconv.ParseUint(f[3], 16, 8)
		if err != nil {
			return out, fmt.Errorf("bad state %q", f[3])
		}
		uid, _ := strconv.ParseUint(f[7], 10, 32)
		ino, err := strconv.ParseUint(f[9], 10, 64)
		if err != nil {
			return out, fmt.Errorf("bad inode %q", f[9])
		}
		out = append(out, sock{Proto: proto, Family: family, Local: local, Remote: remote, State: uint8(st), UID: uint32(uid), Inode: ino})
	}
	return out, sc.Err()
}

func parseHexAddr(s string) (netip.AddrPort, error) {
	a, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("bad address %q", s)
	}
	raw, err := hex.DecodeString(a)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, fmt.Errorf("bad address %q", s)
	}
	// Each 32-bit word was printed as a native-endian integer.
	b := make([]byte, len(raw))
	for i := 0; i < len(raw); i += 4 {
		binary.NativeEndian.PutUint32(b[i:], binary.BigEndian.Uint32(raw[i:]))
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("bad port in %q", s)
	}
	addr, _ := netip.AddrFromSlice(b)
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

// Layout of struct inet_diag_msg (include/uapi/linux/inet_diag.h).
const (
	diagMsgLen    = 72
	diagSockIDOff = 4
)

// parseDiagMsg decodes one inet_diag_msg.
func parseDiagMsg(b []byte, proto string) (sock, bool) {
	if len(b) < diagMsgLen {
		return sock{}, false
	}
	family := 4
	alen := 4
	if b[0] == 10 { // AF_INET6
		family, alen = 6, 16
	}
	id := b[diagSockIDOff:]
	sport := binary.BigEndian.Uint16(id[0:])
	dport := binary.BigEndian.Uint16(id[2:])
	src, _ := netip.AddrFromSlice(id[4 : 4+alen])
	dst, _ := netip.AddrFromSlice(id[20 : 20+alen])
	return sock{
		Proto:  proto,
		Family: family,
		Local:  netip.AddrPortFrom(src, sport),
		Remote: netip.AddrPortFrom(dst, dport),
		State:  b[1],
		UID:    binary.NativeEndian.Uint32(b[64:]),
		Inode:  uint64(binary.NativeEndian.Uint32(b[68:])),
	}, true
}

// diagRequest builds a struct inet_diag_req_v2 asking for every socket of a
// family and protocol, in all states.
func diagRequest(family, protocol uint8) []byte {
	req := make([]byte, 56)
	req[0] = family
	req[1] = protocol
	binary.NativeEndian.PutUint32(req[4:], 0xffffffff)
	return req
}
