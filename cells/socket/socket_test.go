package socket

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenCanaries(t *testing.T) {
	cs, err := openCanaries(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	if len(cs.socks) != 2 || len(cs.fds) != 2 {
		t.Fatalf("want 2 canary sockets, got %d socks and %d fds", len(cs.socks), len(cs.fds))
	}
	for i, proto := range []string{"tcp", "udp"} {
		s := cs.socks[i]
		addr, ok := strings.CutPrefix(s.label, proto+" socket ")
		if s.proto != proto || !ok {
			t.Fatalf("sock %d: proto %q label %q, want %s", i, s.proto, s.label, proto)
		}
		ap, err := netip.ParseAddrPort(addr)
		if err != nil || ap.Addr() != netip.AddrFrom4([4]byte{127, 0, 0, 1}) || ap.Port() == 0 {
			t.Errorf("%s canary address %q: want 127.0.0.1 on a kernel-chosen port (err %v)", proto, addr, err)
		}
		var st unix.Stat_t
		if err := unix.Fstat(cs.fds[i], &st); err != nil || st.Ino != s.inode || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
			t.Errorf("%s canary: fd inode %d mode %o, recorded inode %d (err %v)", proto, st.Ino, st.Mode, s.inode, err)
		}
		if !cs.has(key{Proto: proto, Inode: s.inode}) || !cs.hasInode(s.inode) {
			t.Errorf("%s canary inode %d not matched by has/hasInode", proto, s.inode)
		}
		if proto == "tcp" {
			// The TCP canary must be listening, as a rootkit hiding listeners would see it.
			c, err := net.Dial("tcp4", addr)
			if err != nil {
				t.Errorf("TCP canary is not listening: %v", err)
			} else {
				c.Close()
			}
		}
	}

	fds := cs.fds
	cs.Close()
	for _, fd := range fds {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err == nil && st.Mode&unix.S_IFMT == unix.S_IFSOCK {
			t.Errorf("fd %d still open after Close", fd)
		}
	}
}
