// Package netlink sends netlink dump requests and parses the replies. It
// covers the little Zygarde needs (sock_diag, links, qdiscs and tc filters)
// without a dependency on a full netlink library.
package netlink

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Message is one reply message: its type and the payload after the header.
type Message struct {
	Type uint16
	Data []byte
}

// Dump sends a request of type typ with NLM_F_DUMP over a netlink socket of
// protocol proto and returns every reply message until NLMSG_DONE.
func Dump(proto int, typ uint16, body []byte) ([]Message, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return nil, os.NewSyscallError("socket(AF_NETLINK)", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, os.NewSyscallError("bind(AF_NETLINK)", err)
	}

	const seq = 1
	req := make([]byte, unix.NLMSG_HDRLEN+len(body))
	binary.NativeEndian.PutUint32(req[0:], uint32(len(req)))
	binary.NativeEndian.PutUint16(req[4:], typ)
	binary.NativeEndian.PutUint16(req[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(req[8:], seq)
	copy(req[unix.NLMSG_HDRLEN:], body)
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, os.NewSyscallError("sendto(AF_NETLINK)", err)
	}

	var out []Message
	buf := make([]byte, 64*1024)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return out, os.NewSyscallError("recvfrom(AF_NETLINK)", err)
		}
		msgs, err := parse(buf[:n])
		if err != nil {
			return out, err
		}
		for _, m := range msgs {
			if m.seq != seq {
				continue
			}
			switch m.Type {
			case unix.NLMSG_DONE:
				// Some families append an error code to NLMSG_DONE.
				if len(m.Data) >= 4 {
					if code := int32(binary.NativeEndian.Uint32(m.Data)); code < 0 {
						return out, unix.Errno(-code)
					}
				}
				return out, nil
			case unix.NLMSG_ERROR:
				if len(m.Data) >= 4 {
					if code := int32(binary.NativeEndian.Uint32(m.Data)); code < 0 {
						return out, unix.Errno(-code)
					}
				}
				return out, nil
			default:
				out = append(out, Message{Type: m.Type, Data: m.Data})
			}
		}
	}
}

type rawMessage struct {
	Message
	seq uint32
}

// parse splits a datagram into netlink messages.
func parse(b []byte) ([]rawMessage, error) {
	var out []rawMessage
	for len(b) >= unix.NLMSG_HDRLEN {
		l := int(binary.NativeEndian.Uint32(b[0:]))
		if l < unix.NLMSG_HDRLEN || l > len(b) {
			return out, fmt.Errorf("malformed netlink message (length %d of %d)", l, len(b))
		}
		data := make([]byte, l-unix.NLMSG_HDRLEN)
		copy(data, b[unix.NLMSG_HDRLEN:l])
		out = append(out, rawMessage{
			Message: Message{Type: binary.NativeEndian.Uint16(b[4:]), Data: data},
			seq:     binary.NativeEndian.Uint32(b[8:]),
		})
		adv := (l + unix.NLMSG_ALIGNTO - 1) &^ (unix.NLMSG_ALIGNTO - 1)
		if adv >= len(b) {
			break
		}
		b = b[adv:]
	}
	return out, nil
}

// Attrs parses a sequence of route attributes (struct rtattr / nlattr) into
// a map by type. Nested and byte-order flags are stripped from the type.
func Attrs(b []byte) map[uint16][]byte {
	out := make(map[uint16][]byte)
	for len(b) >= 4 {
		l := int(binary.NativeEndian.Uint16(b[0:]))
		t := binary.NativeEndian.Uint16(b[2:]) & 0x3fff // NLA_F_NESTED, NLA_F_NET_BYTEORDER
		if l < 4 || l > len(b) {
			break
		}
		out[t] = b[4:l]
		adv := (l + 3) &^ 3
		if adv > len(b) {
			break
		}
		b = b[adv:]
	}
	return out
}

// Uint32 decodes a native-endian u32 attribute.
func Uint32(b []byte) (uint32, bool) {
	if len(b) < 4 {
		return 0, false
	}
	return binary.NativeEndian.Uint32(b), true
}

// String decodes a NUL-terminated string attribute.
func String(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// ErrUnsupported reports whether err means the kernel lacks the requested
// netlink family or handler (e.g. a sock_diag module that isn't available).
func ErrUnsupported(err error) bool {
	return errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EPROTONOSUPPORT) ||
		errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EINVAL)
}
