package bpfprog

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/netlink"
)

// Netlink attributes not in x/sys/unix (include/uapi/linux/if_link.h,
// pkt_cls.h, rtnetlink.h).
const (
	iflaXDPAttached = 2
	iflaXDPProgID   = 4
	iflaXDPDrvID    = 5
	iflaXDPSkbID    = 6
	iflaXDPHwID     = 7
	xdpAttachedMany = 4

	tcaKind    = 1
	tcaOptions = 2
	tcaBPFName = 7
	tcaBPFID   = 11

	tcHMinIngress = 0xfff2
	tcHMinEgress  = 0xfff3

	sizeofTcMsg = 20 // struct tcmsg
)

// interfaces maps interface indexes to names and returns the XDP programs
// attached to each (RTM_GETLINK, as `ip link` shows them). XDP attached
// through a BPF link shows up here too.
func interfaces() (map[uint32]string, []attachment, error) {
	msgs, err := netlink.Dump(unix.NETLINK_ROUTE, unix.RTM_GETLINK, make([]byte, unix.SizeofIfInfomsg))
	if err != nil {
		return nil, nil, fmt.Errorf("RTM_GETLINK: %w", err)
	}
	names := map[uint32]string{}
	var xdp []attachment
	for _, m := range msgs {
		if m.Type != unix.RTM_NEWLINK || len(m.Data) < unix.SizeofIfInfomsg {
			continue
		}
		idx := binary.NativeEndian.Uint32(m.Data[4:])
		attrs := netlink.Attrs(m.Data[unix.SizeofIfInfomsg:])
		name := netlink.String(attrs[unix.IFLA_IFNAME])
		names[idx] = name
		x, ok := attrs[unix.IFLA_XDP]
		if !ok {
			continue
		}
		xa := netlink.Attrs(x)
		mode := byte(0)
		if b := xa[iflaXDPAttached]; len(b) > 0 {
			mode = b[0]
		}
		modes := map[uint16]string{iflaXDPDrvID: "driver", iflaXDPSkbID: "generic", iflaXDPHwID: "offloaded"}
		if mode != xdpAttachedMany {
			if id, ok := netlink.Uint32(xa[iflaXDPProgID]); ok && id != 0 {
				label := map[byte]string{1: "driver", 2: "generic", 3: "offloaded"}[mode]
				xdp = append(xdp, attachment{ProgID: id, Where: fmt.Sprintf("XDP (%s) on %s", label, name), Via: "netlink (ip link)", Net: true})
			}
			continue
		}
		for a, label := range modes {
			if id, ok := netlink.Uint32(xa[a]); ok && id != 0 {
				xdp = append(xdp, attachment{ProgID: id, Where: fmt.Sprintf("XDP (%s) on %s", label, name), Via: "netlink (ip link)", Net: true})
			}
		}
	}
	return names, xdp, nil
}

// tcAttachments lists BPF tc filters (cls_bpf) attached to every qdisc's
// filter block, plus the clsact ingress and egress hooks (as `tc filter
// show` and `bpftool net` do). Filters on classes of classful qdiscs and
// BPF tc actions (act_bpf) are not covered.
func tcAttachments(names map[uint32]string) ([]attachment, error) {
	msgs, err := netlink.Dump(unix.NETLINK_ROUTE, unix.RTM_GETQDISC, make([]byte, sizeofTcMsg))
	if err != nil {
		return nil, fmt.Errorf("RTM_GETQDISC: %w", err)
	}
	type block struct {
		ifindex, parent uint32
		hook            string
	}
	var blocks []block
	for _, m := range msgs {
		if m.Type != unix.RTM_NEWQDISC || len(m.Data) < sizeofTcMsg {
			continue
		}
		ifindex := binary.NativeEndian.Uint32(m.Data[4:])
		handle := binary.NativeEndian.Uint32(m.Data[8:])
		kind := netlink.String(netlink.Attrs(m.Data[sizeofTcMsg:])[tcaKind])
		if kind == "clsact" {
			major := handle & 0xffff0000
			blocks = append(blocks, block{ifindex, major | tcHMinIngress, "tc ingress"}, block{ifindex, major | tcHMinEgress, "tc egress"})
			continue
		}
		hook := "tc " + kind + " qdisc"
		if kind == "ingress" {
			hook = "tc ingress"
		}
		blocks = append(blocks, block{ifindex, handle, hook})
	}

	var out []attachment
	for _, b := range blocks {
		req := make([]byte, sizeofTcMsg)
		binary.NativeEndian.PutUint32(req[4:], b.ifindex)
		binary.NativeEndian.PutUint32(req[12:], b.parent)
		filters, err := netlink.Dump(unix.NETLINK_ROUTE, unix.RTM_GETTFILTER, req)
		if err != nil {
			continue // qdisc without a filter block, or gone meanwhile
		}
		for _, f := range filters {
			if f.Type != unix.RTM_NEWTFILTER || len(f.Data) < sizeofTcMsg {
				continue
			}
			attrs := netlink.Attrs(f.Data[sizeofTcMsg:])
			if netlink.String(attrs[tcaKind]) != "bpf" {
				continue
			}
			opts := netlink.Attrs(attrs[tcaOptions])
			id, ok := netlink.Uint32(opts[tcaBPFID])
			if !ok {
				continue // classic BPF bytecode, not an eBPF program
			}
			name := names[b.ifindex]
			if name == "" {
				name = fmt.Sprintf("ifindex %d", b.ifindex)
			}
			out = append(out, attachment{
				ProgID: id, Where: b.hook + " on " + name, Via: "netlink (tc filter)", Net: true,
				TCName: netlink.String(opts[tcaBPFName]),
			})
		}
	}
	return out, nil
}
