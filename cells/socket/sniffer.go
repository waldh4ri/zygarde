package socket

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fdowner"
	"github.com/waldh4ri/zygarde/internal/fsutil"
	"github.com/waldh4ri/zygarde/internal/netlink"
)

// include/uapi/linux/packet_diag.h
const (
	packetShowFilter = 0x20 // PACKET_SHOW_FILTER
	packetDiagFilter = 7    // PACKET_DIAG_FILTER: array of struct sock_filter
	packetDiagReqLen = 20   // sizeof(struct packet_diag_req)
	packetDiagMsgLen = 16   // sizeof(struct packet_diag_msg)
	sockFilterLen    = 8    // sizeof(struct sock_filter)
)

// cBPF opcode for "jump if A == k" (BPF_JMP|BPF_JEQ|BPF_K): how filters
// compare packet fields with magic values.
const bpfJeqK = 0x15

// packetFilter is the classic BPF filter attached to an AF_PACKET socket.
type packetFilter struct {
	Insns     int      // number of instructions
	Constants []uint32 // distinct values the filter compares packet fields with
}

// packetDiagRequest asks sock_diag for every AF_PACKET socket in the caller's
// network namespace, with its socket filter (needs CAP_NET_ADMIN).
func packetDiagRequest() []byte {
	b := make([]byte, packetDiagReqLen)
	b[0] = unix.AF_PACKET
	binary.NativeEndian.PutUint32(b[8:], packetShowFilter)
	return b
}

// parsePacketDiag decodes one packet_diag_msg reply: the socket inode and its
// classic BPF filter, if one is attached. Sockets filtered with an eBPF
// program (SO_ATTACH_BPF) have no classic program to report; the
// hidden_ebpf_program Cell covers those.
func parsePacketDiag(b []byte) (uint64, *packetFilter, bool) {
	if len(b) < packetDiagMsgLen {
		return 0, nil, false
	}
	ino := uint64(binary.NativeEndian.Uint32(b[4:]))
	raw, ok := netlink.Attrs(b[packetDiagMsgLen:])[packetDiagFilter]
	if !ok || len(raw) < sockFilterLen {
		return ino, nil, true
	}
	f := &packetFilter{Insns: len(raw) / sockFilterLen}
	seen := map[uint32]bool{}
	for i := 0; i+sockFilterLen <= len(raw); i += sockFilterLen {
		code := binary.NativeEndian.Uint16(raw[i:])
		k := binary.NativeEndian.Uint32(raw[i+4:])
		if code == bpfJeqK && !seen[k] {
			seen[k] = true
			f.Constants = append(f.Constants, k)
		}
	}
	return ino, f, true
}

// readPacketFilters returns the classic BPF filter of every AF_PACKET socket
// that has one, keyed by inode. It fails when the kernel has no packet_diag
// (CONFIG_PACKET_DIAG) or refused the dump.
func readPacketFilters() (map[uint64]*packetFilter, error) {
	msgs, err := fsutil.WithCommVal("ss", func() ([]netlink.Message, error) {
		return netlink.Dump(unix.NETLINK_SOCK_DIAG, unix.SOCK_DIAG_BY_FAMILY, packetDiagRequest())
	})
	if err != nil {
		return nil, err
	}
	out := map[uint64]*packetFilter{}
	for _, m := range msgs {
		if ino, f, ok := parsePacketDiag(m.Data); ok && f != nil {
			out[ino] = f
		}
	}
	return out, nil
}

// sniffingProtocols are the ethertypes a packet socket binds to in order to
// read IP traffic (include/uapi/linux/if_ether.h).
var sniffingProtocols = map[uint16]string{
	0x0003: "ETH_P_ALL",
	0x0800: "ETH_P_IP",
	0x86dd: "ETH_P_IPV6",
}

// networkTools are programs that legitimately read IP traffic from AF_PACKET
// sockets: DHCP clients and servers, network managers, VRRP/LACP/IS-IS
// daemons, capture and IDS tools. Matched on the executable's base name, and
// only when it lives in a system directory.
var networkTools = map[string]bool{
	// DHCP clients, servers and relays
	"dhclient": true, "dhcpcd": true, "udhcpc": true, "udhcpd": true, "dhcpd": true, "dhcrelay": true,
	"kea-dhcp4": true, "kea-dhcp6": true, "dnsmasq": true, "busybox": true, "nm-dhcp-helper": true,
	"dhcp": true, // CNI DHCP plugin daemon
	// network managers and link-layer daemons
	"NetworkManager": true, "systemd-networkd": true, "wpa_supplicant": true, "hostapd": true,
	"connmand": true, "wicked": true, "wickedd-dhcp4": true, "wickedd-dhcp6": true, "iwd": true,
	"lldpd": true, "ladvd": true, "lldpad": true, "teamd": true, "mstpd": true, "ptp4l": true,
	"avahi-autoipd": true, "pppd": true, "pppoe": true, "pppoe-server": true, "arping": true,
	"keepalived": true, "isisd": true, "radvd": true, "ndppd": true, "ovs-vswitchd": true,
	// capture, monitoring and IDS
	"tcpdump": true, "dumpcap": true, "tshark": true, "wireshark": true, "nmap": true, "p0f": true,
	"suricata": true, "snort": true, "zeek": true, "bro": true, "arpwatch": true, "iftop": true,
	"nethogs": true, "darkstat": true, "ntopng": true, "pmacctd": true, "softflowd": true, "fprobe": true,
}

// systemExe reports whether an executable path is in a directory packages
// install to, and not deleted.
func systemExe(exe string) bool {
	if exe == "" || strings.HasSuffix(exe, " (deleted)") {
		return false
	}
	for _, d := range []string{"/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/snap/", "/nix/store/"} {
		if strings.HasPrefix(exe, d) {
			return true
		}
	}
	return false
}

// knownSniffer reports whether exe is a recognised network tool installed in
// a system directory.
func knownSniffer(exe string) bool {
	return systemExe(exe) && networkTools[filepath.Base(exe)]
}

type sniffHolder struct {
	pid  uint32
	comm string
	exe  string
}

// packetHolders lists the processes holding each packet socket, from the
// kernel task file tables when available, otherwise from /proc/<pid>/fd.
func packetHolders(table *fdowner.Table, inodes map[uint64]bool) map[uint64][]sniffHolder {
	out := map[uint64][]sniffHolder{}
	add := func(ino uint64, pid uint32, comm string) {
		exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if comm == "" {
			b, _ := fsutil.ReadFileNoAtime(fmt.Sprintf("/proc/%d/comm", pid))
			comm = strings.TrimSpace(string(b))
		}
		out[ino] = append(out[ino], sniffHolder{pid: pid, comm: comm, exe: exe})
	}
	if table != nil {
		for ino := range inodes {
			for _, h := range table.Holders(fdowner.Socket, ino) {
				add(ino, h.TGID, h.Comm)
			}
		}
		return out
	}
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range ents {
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		fds, err := os.ReadDir("/proc/" + e.Name() + "/fd")
		if err != nil {
			continue
		}
		held := map[uint64]bool{}
		for _, fd := range fds {
			target, err := os.Readlink("/proc/" + e.Name() + "/fd/" + fd.Name())
			if err != nil || !strings.HasPrefix(target, "socket:[") {
				continue
			}
			ino, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]"), 10, 64)
			if err == nil && inodes[ino] && !held[ino] {
				held[ino] = true
				add(ino, uint32(pid), "")
			}
		}
	}
	return out
}

// checkSniffers flags AF_PACKET sockets that read IP traffic for a program
// that is not a recognised network tool installed in a system directory.
// This is how passive backdoors such as BPFDoor wait for their magic packet:
// a raw packet socket, usually narrowed by a classic BPF filter, sees traffic
// before the firewall and opens no port. It returns the number of findings.
func (c *Cell) checkSniffers(rec *core.Recorder, table *fdowner.Table, pkts []packetSock) int {
	if len(pkts) == 0 {
		return 0
	}
	filters, err := readPacketFilters()
	if err != nil {
		if netlink.ErrUnsupported(err) {
			rec.Limit("AF_PACKET socket filters not read: the kernel has no packet sock_diag (CONFIG_PACKET_DIAG)")
		} else {
			rec.Limit("AF_PACKET socket filters not read: %v", err)
		}
		filters = map[uint64]*packetFilter{}
	}

	inodes := map[uint64]bool{}
	for _, p := range pkts {
		inodes[p.Inode] = true
	}
	holders := packetHolders(table, inodes)

	sort.Slice(pkts, func(i, j int) bool { return pkts[i].Inode < pkts[j].Inode })
	found := 0
	for _, p := range pkts {
		f := filters[p.Inode]
		hs := holders[p.Inode]
		protoName, sniffing := sniffingProtocols[p.Proto]
		if !sniffing || len(hs) == 0 {
			continue
		}
		trusted := false
		for _, h := range hs {
			trusted = trusted || knownSniffer(h.exe)
		}
		if trusted {
			continue
		}
		// The holder must still be alive: a process that exited between
		// reads is not worth a finding.
		alive := false
		for _, h := range hs {
			alive = alive || unix.Kill(int(h.pid), 0) == nil
		}
		if !alive {
			continue
		}
		found++
		names := make([]string, 0, len(hs))
		exes := make([]string, 0, len(hs))
		for _, h := range hs {
			names = append(names, fmt.Sprintf("%d (%s)", h.pid, h.comm))
			exes = append(exes, h.exe)
		}
		d := map[string]string{
			"inode":    strconv.FormatUint(p.Inode, 10),
			"protocol": fmt.Sprintf("0x%04x (%s)", p.Proto, protoName),
			"ifindex":  strconv.Itoa(p.Ifindex),
			"uid":      strconv.FormatUint(uint64(p.UID), 10),
			"held_by":  strings.Join(names, ", "),
			"exe":      strings.Join(exes, ", "),
		}
		what := "without a filter"
		if f != nil {
			what = fmt.Sprintf("with a %d-instruction classic BPF filter", f.Insns)
			d["bpf_filter_instructions"] = strconv.Itoa(f.Insns)
			if len(f.Constants) > 0 {
				ks := make([]string, len(f.Constants))
				for i, k := range f.Constants {
					ks[i] = fmt.Sprintf("0x%x", k)
				}
				d["bpf_filter_constants"] = strings.Join(ks, ", ")
			}
		}
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("Process %s sniffs IP traffic on a raw AF_PACKET socket %s", names[0], what),
			Details:     d,
			Why: "A raw packet socket receives every matching frame before the firewall and needs no open port. " +
				"Passive backdoors (BPFDoor and its variants) sit on one, with a classic BPF filter that passes only " +
				"their magic packet, and spawn a shell when it arrives. The program holding this socket is not a " +
				"recognised network tool installed in a system directory. The filter's constants (bpf_filter_constants) " +
				"often include the magic value or the ports it listens on.",
			Benign: "Packet capture or monitoring software not in Zygarde's list (a custom DHCP client, IDS sensor or " +
				"pcap-based agent). Check which package owns the executable (dpkg -S, rpm -qf) and dump the filter with `ss -0 -b -p`.",
		})
	}
	return found
}

// rawTools are programs that legitimately hold SOCK_RAW IP sockets: ping and
// traceroute style tools, IPv6 neighbour/router discovery in network
// managers, routing and VRRP daemons, VPN/IPsec daemons.
var rawTools = map[string]bool{
	"ping": true, "ping6": true, "mtr": true, "mtr-packet": true, "traceroute": true, "tracepath": true,
	"fping": true, "hping3": true, "arping": true, "nmap": true, "tcptraceroute": true, "oping": true,
	"systemd-networkd": true, "NetworkManager": true, "wpa_supplicant": true, "connmand": true, "wicked": true,
	"wickedd-auto4": true, "wickedd-dhcp6": true, "dhcpcd": true, "dhclient": true, "radvd": true, "ndppd": true,
	"rdisc6": true, "rdnssd": true, "dibbler-client": true, "odhcp6c": true, "dnsmasq": true, "unbound": false,
	"keepalived": true, "bird": true, "bird6": true, "bgpd": true, "ospfd": true, "ospf6d": true, "ripd": true,
	"ripngd": true, "isisd": true, "zebra": true, "pimd": true, "pim6d": true, "babeld": true, "eigrpd": true,
	"smcrouted": true, "igmpproxy": true, "mrouted": true, "pppd": true, "pppoe": true, "pppoe-server": true,
	"charon": true, "charon-systemd": true, "pluto": true, "racoon": true, "openvpn": false, "wg": false,
	"lldpd": true, "ovs-vswitchd": true, "snmpd": true, "smokeping": true, "chronyd": false, "ntpd": false,
	"suricata": true, "snort": true, "zeek": true, "tcpdump": true, "dumpcap": true, "tshark": true,
	"calico-node": true, "felix": true, "cilium-agent": true, "kube-proxy": true,
}

// knownRawTool reports whether exe is a recognised raw-socket user installed
// in a system directory.
func knownRawTool(exe string) bool {
	return systemExe(exe) && rawTools[filepath.Base(exe)]
}

// checkRawSockets flags SOCK_RAW IP sockets held by a live program that is not
// a recognised network tool in a system directory. A raw ICMP or TCP socket is
// how backdoors such as Prism and many "ICMP shells" wait for a trigger packet
// without listening on a port. It returns the number of findings.
func (c *Cell) checkRawSockets(rec *core.Recorder, table *fdowner.Table, raws []sock) int {
	if len(raws) == 0 {
		return 0
	}
	inodes := map[uint64]bool{}
	for _, r := range raws {
		inodes[r.Inode] = true
	}
	holders := packetHolders(table, inodes)
	selfExe, _ := os.Readlink("/proc/self/exe")

	sort.Slice(raws, func(i, j int) bool { return raws[i].Inode < raws[j].Inode })
	found := 0
	for _, r := range raws {
		hs := holders[r.Inode]
		if len(hs) == 0 {
			continue
		}
		trusted, alive := false, false
		for _, h := range hs {
			trusted = trusted || knownRawTool(h.exe) || (selfExe != "" && h.exe == selfExe)
			alive = alive || unix.Kill(int(h.pid), 0) == nil
		}
		if trusted || !alive {
			continue
		}
		found++
		names := make([]string, 0, len(hs))
		exes := make([]string, 0, len(hs))
		for _, h := range hs {
			names = append(names, fmt.Sprintf("%d (%s)", h.pid, h.comm))
			exes = append(exes, h.exe)
		}
		proto := int(r.Local.Port()) // /proc/net/raw shows the IP protocol number as the port
		d := details(r, nil)
		d["ip_protocol"] = fmt.Sprintf("%d (%s)", proto, ipProtoName(proto))
		d["held_by"] = strings.Join(names, ", ")
		d["exe"] = strings.Join(exes, ", ")
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("Process %s holds a raw IP socket for protocol %s", names[0], ipProtoName(proto)),
			Details:     d,
			Why: "A raw IP socket receives every packet of its protocol (ICMP, TCP, ...) before any port is involved, " +
				"so it needs no listener. Backdoors such as Prism and ICMP shells wait on one for a trigger packet. " +
				"The program holding it is not a recognised network tool installed in a system directory.",
			Benign: "Monitoring, ping or routing software not in Zygarde's list. Check which package owns the executable " +
				"(dpkg -S, rpm -qf) and what it does with the socket.",
		})
	}
	return found
}

func ipProtoName(p int) string {
	switch p {
	case 1:
		return "ICMP"
	case 2:
		return "IGMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 41:
		return "IPv6"
	case 47:
		return "GRE"
	case 58:
		return "ICMPv6"
	case 89:
		return "OSPF"
	case 112:
		return "VRRP"
	case 255:
		return "RAW"
	}
	return strconv.Itoa(p)
}
