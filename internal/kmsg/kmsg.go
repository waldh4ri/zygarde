// Package kmsg reads the kernel log from /dev/kmsg and extracts kernel oopses
// from it.
//
// A kernel oops while root reads ordinary sysfs or procfs files is not
// something a healthy kernel does: it means the kernel followed a corrupt or
// dangling pointer behind that file, which is what a rootkit leaves when it
// frees or overwrites kernel objects to hide (Diamorphine frees its module's
// section attributes). Zygarde therefore treats an oops as evidence, not just
// as an error.
package kmsg

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Device is the kernel log device.
const Device = "/dev/kmsg"

// Record is one kernel log record.
type Record struct {
	Seq    uint64
	TimeUS int64 // microseconds since boot
	Msg    string
}

// Read returns every record currently in the kernel ring buffer, oldest
// first. It does not block.
func Read() ([]Record, error) {
	return readFrom(Device)
}

func readFrom(path string) ([]Record, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer unix.Close(fd)
	var out []Record
	buf := make([]byte, 16<<10)
	for {
		n, err := unix.Read(fd, buf)
		switch {
		case err == nil:
			if r, ok := parseRecord(string(buf[:n])); ok {
				out = append(out, r)
			}
		case errors.Is(err, unix.EAGAIN):
			return out, nil
		case errors.Is(err, unix.EPIPE):
			// The reader fell behind and records were overwritten: go on.
		case errors.Is(err, unix.EINTR):
		default:
			if len(out) > 0 {
				return out, nil
			}
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
	}
}

// parseRecord parses "prio,seq,usec,flags[,...];message\n[ KEY=VALUE\n...]".
func parseRecord(s string) (Record, bool) {
	head, rest, ok := strings.Cut(s, ";")
	if !ok {
		return Record{}, false
	}
	f := strings.Split(head, ",")
	if len(f) < 3 {
		return Record{}, false
	}
	seq, err1 := strconv.ParseUint(f[1], 10, 64)
	us, err2 := strconv.ParseInt(f[2], 10, 64)
	if err1 != nil || err2 != nil {
		return Record{}, false
	}
	msg, _, _ := strings.Cut(rest, "\n") // later lines are KEY=VALUE continuations
	return Record{Seq: seq, TimeUS: us, Msg: msg}, true
}

// LastSeq returns the highest sequence number in recs, or 0.
func LastSeq(recs []Record) uint64 {
	var last uint64
	for _, r := range recs {
		if r.Seq > last {
			last = r.Seq
		}
	}
	return last
}

// Oops is one kernel oops, BUG or panic found in the log.
type Oops struct {
	Seq      uint64
	TimeUS   int64
	Headline string   // e.g. "general protection fault, probably for non-canonical address ..."
	Comm     string   // faulting task
	PID      int      // faulting thread
	IP       string   // function the fault happened in, e.g. "sysfs_kf_bin_read+0x57/0x70"
	Trace    []string // reliable call-trace frames, innermost first
}

// Summary is a one-line description: the kind of fault and where it happened.
func (o Oops) Summary() string {
	kind := strings.TrimPrefix(o.Headline, "BUG: ")
	for _, sep := range []string{":", ",", " for address", " at "} {
		if i := strings.Index(kind, sep); i > 0 {
			kind = kind[:i]
		}
	}
	switch {
	case strings.HasPrefix(o.IP, "0x"):
		// The CPU jumped to an address no kernel symbol covers: freed or
		// overwritten memory used as code or as a function pointer.
		return kind + " jumping to " + o.IP + ", which is not a kernel symbol"
	case o.IP != "":
		return kind + " in " + o.IP
	}
	return kind
}

var (
	headlines = []string{
		"general protection fault", "BUG: kernel NULL pointer dereference", "BUG: unable to handle",
		"kernel BUG at ", "Unable to handle kernel ", "Internal error: Oops", "invalid opcode:",
		"double fault", "Kernel panic - not syncing", "BUG: scheduling while atomic", "BUG: soft lockup",
	}
	cpuPID   = regexp.MustCompile(`\bCPU: \d+ .*?\bPID: (\d+) Comm: (\S+)`)
	frameRE  = regexp.MustCompile(`^\s+(?:\? )?([A-Za-z0-9_.$]+)\+0x[0-9a-f]+/0x[0-9a-f]+`)
	unsureRE = regexp.MustCompile(`^\s+\?`)
)

// maxEventRecords bounds how many records after a headline belong to it.
const maxEventRecords = 150

// Oopses extracts the oopses whose records come after afterSeq (0 for all),
// oldest first.
func Oopses(recs []Record, afterSeq uint64) []Oops {
	var out []Oops
	var cur *Oops
	left := 0
	inTrace := false
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}
	for _, r := range recs {
		if r.Seq <= afterSeq {
			continue
		}
		if h := isHeadline(r.Msg); h {
			// A new event unless this is the tail of the one being read
			// ("Oops: 0000 [#1]" follows the headline; a headline inside the
			// window of another is a separate event).
			flush()
			cur = &Oops{Seq: r.Seq, TimeUS: r.TimeUS, Headline: r.Msg}
			left, inTrace = maxEventRecords, false
			continue
		}
		if cur == nil {
			continue
		}
		if left--; left < 0 || strings.HasPrefix(r.Msg, "---[ end trace") {
			flush()
			continue
		}
		switch {
		case cur.PID == 0 && cpuPID.MatchString(r.Msg):
			m := cpuPID.FindStringSubmatch(r.Msg)
			cur.PID, _ = strconv.Atoi(m[1])
			cur.Comm = m[2]
		case cur.IP == "" && strings.HasPrefix(r.Msg, "RIP: 0010:"):
			cur.IP = firstField(strings.TrimPrefix(r.Msg, "RIP: 0010:"))
		case cur.IP == "" && strings.HasPrefix(r.Msg, "pc : "):
			cur.IP = firstField(strings.TrimPrefix(r.Msg, "pc : "))
		case strings.HasPrefix(r.Msg, "Call Trace") || strings.HasPrefix(r.Msg, "Call trace"):
			inTrace = true
		case inTrace:
			if m := frameRE.FindStringSubmatch(r.Msg); m != nil {
				if !unsureRE.MatchString(r.Msg) && len(cur.Trace) < 8 {
					cur.Trace = append(cur.Trace, m[1])
				}
			} else if !strings.HasPrefix(strings.TrimSpace(r.Msg), "<") {
				inTrace = false // "RIP: 0033:", "Code:", ...: the trace is over
			}
		}
	}
	flush()
	return out
}

func isHeadline(msg string) bool {
	for _, h := range headlines {
		if strings.HasPrefix(msg, h) {
			return true
		}
	}
	return false
}

func firstField(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}
