package socket

import (
	"encoding/binary"
	"testing"
)

// diagReply builds a packet_diag_msg for inode ino with an optional
// PACKET_DIAG_FILTER attribute holding insns.
func diagReply(ino uint32, insns [][4]uint32) []byte {
	b := make([]byte, packetDiagMsgLen)
	b[0] = 17 // AF_PACKET
	b[1] = 3  // SOCK_RAW
	binary.NativeEndian.PutUint32(b[4:], ino)
	if insns == nil {
		return b
	}
	attr := make([]byte, 4+len(insns)*sockFilterLen)
	binary.NativeEndian.PutUint16(attr[0:], uint16(len(attr)))
	binary.NativeEndian.PutUint16(attr[2:], packetDiagFilter)
	for i, in := range insns {
		o := 4 + i*sockFilterLen
		binary.NativeEndian.PutUint16(attr[o:], uint16(in[0]))
		attr[o+2] = uint8(in[1])
		attr[o+3] = uint8(in[2])
		binary.NativeEndian.PutUint32(attr[o+4:], in[3])
	}
	return append(b, attr...)
}

func TestParsePacketDiag(t *testing.T) {
	// Start of the filter a BPFDoor variant attached (ss -0 -b):
	// ldh [12]; jeq #0x86dd; ldb [20]; jeq #17; ldh [56]; jeq #53; jeq #0x800
	insns := [][4]uint32{
		{0x28, 0, 0, 12}, {0x15, 0, 4, 0x86dd}, {0x30, 0, 0, 20}, {0x15, 0, 11, 17},
		{0x28, 0, 0, 56}, {0x15, 8, 9, 53}, {0x15, 0, 8, 0x800}, {0x15, 0, 1, 17},
	}
	ino, f, ok := parsePacketDiag(diagReply(14123, insns))
	if !ok || ino != 14123 || f == nil {
		t.Fatalf("got ino=%d filter=%v ok=%v", ino, f, ok)
	}
	if f.Insns != len(insns) {
		t.Errorf("Insns = %d, want %d", f.Insns, len(insns))
	}
	want := []uint32{0x86dd, 17, 53, 0x800} // distinct, in order
	if len(f.Constants) != len(want) {
		t.Fatalf("Constants = %#x, want %#x", f.Constants, want)
	}
	for i := range want {
		if f.Constants[i] != want[i] {
			t.Errorf("Constants[%d] = %#x, want %#x", i, f.Constants[i], want[i])
		}
	}

	ino, f, ok = parsePacketDiag(diagReply(99, nil))
	if !ok || ino != 99 || f != nil {
		t.Errorf("no filter: got ino=%d filter=%v ok=%v", ino, f, ok)
	}
	if _, _, ok := parsePacketDiag(make([]byte, 8)); ok {
		t.Error("short message parsed")
	}
}

func TestPacketDiagRequest(t *testing.T) {
	b := packetDiagRequest()
	if len(b) != packetDiagReqLen || b[0] != 17 || b[1] != 0 {
		t.Fatalf("bad request header % x", b)
	}
	if binary.NativeEndian.Uint32(b[8:]) != packetShowFilter {
		t.Errorf("pdiag_show = %#x", binary.NativeEndian.Uint32(b[8:]))
	}
}

func TestKnownSniffer(t *testing.T) {
	for exe, want := range map[string]bool{
		"/usr/sbin/dhclient":                         true,
		"/usr/lib/systemd/systemd-networkd":          true,
		"/usr/sbin/NetworkManager":                   true,
		"/usr/bin/tcpdump":                           true,
		"/usr/sbin/tcpdump (deleted)":                false, // replaced or removed binary
		"/dev/shm/dhclient":                          false, // name borrowed outside a system dir
		"/var/run/haldrund":                          false,
		"/usr/sbin/haldrund":                         false, // unknown program in a system dir
		"/opt/s/r3/349f3adc71799dc976e59af0ad60c284": false,
		"": false,
	} {
		if got := knownSniffer(exe); got != want {
			t.Errorf("knownSniffer(%q) = %v, want %v", exe, got, want)
		}
	}
}

func TestKnownRawTool(t *testing.T) {
	for exe, want := range map[string]bool{
		"/usr/bin/ping":                     true,
		"/usr/lib/systemd/systemd-networkd": true,
		"/usr/sbin/NetworkManager":          true,
		"/usr/sbin/chronyd":                 false, // raw sockets not needed
		"/tmp/ping":                         false,
		"/opt/s/r7/9bef40c4db24a7bd8a9b8dd6548a27199bc44185bfacd67920d885e0cd2a1555": false,
	} {
		if got := knownRawTool(exe); got != want {
			t.Errorf("knownRawTool(%q) = %v, want %v", exe, got, want)
		}
	}
	if ipProtoName(1) != "ICMP" || ipProtoName(58) != "ICMPv6" || ipProtoName(200) != "200" {
		t.Error("ipProtoName")
	}
}
