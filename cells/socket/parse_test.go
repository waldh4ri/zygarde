package socket

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestParseProcNet(t *testing.T) {
	// Real lines from /proc/net/tcp and tcp6 on x86_64 (little endian).
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:B4C2 0100007F:1F90 06 00000000:00000000 03:00000F9D 00000000     0        0 0 3 0000000000000000
`
	socks, err := parseProcNet(strings.NewReader(tcp), "tcp", 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(socks) != 2 {
		t.Fatalf("got %d sockets, want 2", len(socks))
	}
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		t.Skip("address fixtures are little endian")
	}
	s := socks[0]
	if s.Local.String() != "127.0.0.1:8080" || s.State != 10 || s.Inode != 12345 {
		t.Errorf("got %v state=%d inode=%d", s.Local, s.State, s.Inode)
	}
	if s.String() != "TCP4 127.0.0.1:8080 (LISTEN)" {
		t.Errorf("String() = %q", s.String())
	}

	tcp6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 999 1 0000000000000000 100 0 0 10 0
`
	socks, err = parseProcNet(strings.NewReader(tcp6), "tcp", 6)
	if err != nil {
		t.Fatal(err)
	}
	if len(socks) != 1 || socks[0].Local.String() != "[::1]:22" || socks[0].Inode != 999 {
		t.Errorf("got %+v", socks)
	}
}

func TestParseDiagMsg(t *testing.T) {
	b := make([]byte, diagMsgLen)
	b[0] = 2  // AF_INET
	b[1] = 10 // LISTEN
	binary.BigEndian.PutUint16(b[4:], 4444)
	copy(b[8:], []byte{10, 0, 0, 1})
	binary.NativeEndian.PutUint32(b[64:], 1000)
	binary.NativeEndian.PutUint32(b[68:], 777)
	s, ok := parseDiagMsg(b, "tcp")
	if !ok {
		t.Fatal("not parsed")
	}
	if s.Local.String() != "10.0.0.1:4444" || s.State != 10 || s.Inode != 777 || s.UID != 1000 || s.Family != 4 {
		t.Errorf("got %+v", s)
	}
	if _, ok := parseDiagMsg(b[:10], "tcp"); ok {
		t.Error("short message accepted")
	}
}

func TestCompare(t *testing.T) {
	a := sock{Proto: "tcp", Inode: 1}
	b := sock{Proto: "tcp", Inode: 2}
	c := sock{Proto: "udp", Inode: 2}
	src := sources{
		proc:     view{a.key(): a, b.key(): b},
		diag:     view{a.key(): a, c.key(): c},
		compared: map[string]bool{"tcp0": true, "udp0": true},
	}
	onlyProc, onlyDiag := compare(src)
	if len(onlyProc) != 1 || onlyProc[0] != b {
		t.Errorf("onlyProc = %+v", onlyProc)
	}
	if len(onlyDiag) != 1 || onlyDiag[0] != c {
		t.Errorf("onlyDiag = %+v", onlyDiag)
	}
	if got := intersect(onlyProc, []sock{b, c}); len(got) != 1 {
		t.Errorf("intersect = %+v", got)
	}
	if got := intersect(onlyProc, nil); len(got) != 0 {
		t.Errorf("intersect with nothing = %+v", got)
	}
}
