// Package fdowner reads, from the kernel's own task and file tables, which
// processes hold BPF programs, maps, links, BPF-attached perf events and
// sockets. It does not go through /proc, so a process hidden from /proc still
// shows up as the holder of its objects.
package fdowner

//go:generate go tool bpf2go -target amd64,arm64 -cflags "-Wall -Werror -Wno-missing-declarations" -type fd_rec fdowner fdowner.bpf.c -- -I../../bpf/include

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/core"
)

// Kind is the type of object a descriptor refers to.
type Kind uint32

// Kinds, as in fdowner.bpf.c.
const (
	Prog   Kind = 1
	Map    Kind = 2
	Link   Kind = 3
	Perf   Kind = 4 // a perf event (tracepoint, kprobe...) running a BPF program
	Socket Kind = 5
)

func (k Kind) String() string {
	switch k {
	case Prog:
		return "program"
	case Map:
		return "map"
	case Link:
		return "link"
	case Perf:
		return "perf event"
	case Socket:
		return "socket"
	}
	return "unknown"
}

// FD is one descriptor held by a process.
type FD struct {
	TGID   uint32 // in zygarde's PID namespace
	FD     uint32
	Kind   Kind
	ID     uint32 // program, map or link ID
	ProgID uint32 // program run by a link or perf event
	Inode  uint64 // socket inode
	Comm   string
}

// Table is a snapshot of the descriptors of interest across all processes.
type Table struct {
	FDs []FD
	// Learned lists the kinds the scan could recognise; a kind is missing if
	// zygarde could not create an object of that kind to learn it from.
	Learned map[Kind]bool
}

// Supported returns a Skip error if the kernel can't run the file iterator.
func Supported(env *core.Env) error {
	if err := env.RequireBTFType("bpf_iter__task_file", "the BPF task file iterator (Linux 5.8+)"); err != nil {
		return err
	}
	if env.Lockdown == "confidentiality" {
		return core.Skip("kernel lockdown (confidentiality) forbids reading kernel memory from BPF")
	}
	return nil
}

// Snapshot walks every process's file table once.
func Snapshot(env *core.Env) (*Table, error) {
	spec, err := loadFdowner()
	if err != nil {
		return nil, err
	}
	var objs fdownerObjects
	if err := bpfutil.Load(env, spec, &objs); err != nil {
		return nil, err
	}
	defer objs.Close()

	it, err := link.AttachIter(link.IterOptions{Program: objs.DumpFds})
	if err != nil {
		return nil, core.WrapBPF("attach task_file iterator", err)
	}
	defer it.Close()

	// Objects of each kind to learn file_operations from.
	known := map[int]Kind{objs.DumpFds.FD(): Prog, objs.Fops.FD(): Map, it.FD(): Link}
	if fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0); err == nil {
		defer unix.Close(fd)
		known[fd] = Socket
	}
	attr := unix.PerfEventAttr{Type: unix.PERF_TYPE_SOFTWARE, Config: unix.PERF_COUNT_SW_DUMMY, Bits: unix.PerfBitDisabled}
	attr.Size = uint32(unsafe.Sizeof(attr))
	if fd, err := unix.PerfEventOpen(&attr, 0, -1, -1, unix.PERF_FLAG_FD_CLOEXEC); err == nil {
		defer unix.Close(fd)
		known[fd] = Perf
	}

	own, err := read(it)
	if err != nil {
		return nil, err
	}
	t := &Table{Learned: map[Kind]bool{}}
	for _, r := range own {
		k, ok := known[int(r.Fd)]
		if !ok || r.Fop == 0 {
			continue
		}
		if err := objs.Fops.Put(uint32(k), r.Fop); err != nil {
			return nil, core.WrapBPF("update fops map", err)
		}
		t.Learned[k] = true
	}
	if !t.Learned[Prog] {
		return nil, errors.New("task_file iterator did not report zygarde's own BPF program descriptor")
	}

	recs, err := read(it)
	if err != nil {
		return nil, err
	}
	for _, r := range recs {
		t.FDs = append(t.FDs, FD{
			TGID: r.Tgid, FD: r.Fd, Kind: Kind(r.Kind), ID: r.Id, ProgID: r.ProgId,
			Inode: r.Ino, Comm: bpfutil.Int8String(r.Comm[:]),
		})
	}
	return t, nil
}

func read(it *link.Iter) ([]fdownerFdRec, error) {
	rd, err := it.Open()
	if err != nil {
		return nil, core.WrapBPF("open iterator", err)
	}
	defer rd.Close()
	data, err := io.ReadAll(rd)
	if err != nil {
		return nil, fmt.Errorf("reading iterator: %w", err)
	}
	return bpfutil.Decode[fdownerFdRec](data)
}

// Holder is a process holding an object, possibly through several descriptors.
type Holder struct {
	TGID uint32
	Comm string
}

// Holders returns the processes holding an object, sorted by PID. For a
// program, that includes processes holding a link or perf event running it.
func (t *Table) Holders(kind Kind, id uint64) []Holder {
	seen := map[uint32]string{}
	for _, f := range t.FDs {
		match := false
		switch kind {
		case Prog:
			match = (f.Kind == Prog && uint64(f.ID) == id) ||
				((f.Kind == Link || f.Kind == Perf) && uint64(f.ProgID) == id)
		case Socket:
			match = f.Kind == Socket && f.Inode == id
		default:
			match = f.Kind == kind && uint64(f.ID) == id
		}
		if match && f.TGID != 0 {
			seen[f.TGID] = f.Comm
		}
	}
	out := make([]Holder, 0, len(seen))
	for pid, comm := range seen {
		out = append(out, Holder{pid, comm})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TGID < out[j].TGID })
	return out
}

// Of returns the descriptors of one kind.
func (t *Table) Of(kind Kind) []FD {
	var out []FD
	for _, f := range t.FDs {
		if f.Kind == kind {
			out = append(out, f)
		}
	}
	return out
}

// ListedPIDs returns the process IDs listed in /proc. It goes through
// getdents64, which rootkits hook to hide processes.
func ListedPIDs() (map[uint32]bool, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("listing /proc: %w", err)
	}
	pids := make(map[uint32]bool, len(entries))
	for _, e := range entries {
		if pid, err := strconv.ParseUint(e.Name(), 10, 32); err == nil {
			pids[uint32(pid)] = true
		}
	}
	return pids, nil
}

// HiddenOnly reports whether every holder is missing from /proc. It is false
// when there are no holders.
func HiddenOnly(holders []Holder, listed map[uint32]bool) bool {
	if len(holders) == 0 {
		return false
	}
	for _, h := range holders {
		if listed[h.TGID] {
			return false
		}
	}
	return true
}

// StillHidden re-checks holders that looked hidden: each must still exist
// (kill(pid, 0) succeeds) and still be missing from a fresh /proc listing.
// This rules out processes that exited between the two views.
func StillHidden(holders []Holder) bool {
	listed, err := ListedPIDs()
	if err != nil || len(holders) == 0 {
		return false
	}
	for _, h := range holders {
		if listed[h.TGID] || errors.Is(unix.Kill(int(h.TGID), 0), unix.ESRCH) {
			return false
		}
	}
	return true
}

// Describe formats holders as "1234 (comm), 5678 (comm)".
func Describe(holders []Holder) string {
	s := ""
	for i, h := range holders {
		if i > 0 {
			s += ", "
		}
		s += fmt.Sprintf("%d (%s)", h.TGID, h.Comm)
	}
	return s
}
