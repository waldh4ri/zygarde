// Package bpfprog detects eBPF programs hidden from userspace enumeration.
package bpfprog

//go:generate go tool bpf2go -target amd64,arm64 -cflags "-Wall -Werror -Wno-missing-declarations" -type prog_info -type enum_event bpfprog bpfprog.bpf.c -- -I../../bpf/include

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/core"
)

// Cell compares three views of the loaded eBPF programs:
//   - kernel: the bpf_prog iterator walks the kernel's program IDR directly
//   - userspace: BPF_PROG_GET_NEXT_ID, the syscall bpftool and others use
//   - pinned: programs pinned under /sys/fs/bpf
//
// It also traces zygarde's own GET_NEXT_ID calls at syscall exit to catch
// enumeration cut short with a fake -ENOENT, or answers rewritten in memory.
type Cell struct{}

// New returns the hidden eBPF program Cell.
func New() *Cell { return &Cell{} }

func (*Cell) ID() string             { return "hidden_ebpf_program" }
func (*Cell) Name() string           { return "Hidden eBPF Program Detection" }
func (*Cell) Timeout() time.Duration { return 30 * time.Second }
func (*Cell) Description() string {
	return "Compares the kernel's BPF program list (iterator) with BPF_PROG_GET_NEXT_ID enumeration and /sys/fs/bpf pins"
}

func (*Cell) Supported(env *core.Env) error {
	if err := env.RequireBTFType("bpf_iter__bpf_prog", "the BPF program iterator (Linux 5.9+)"); err != nil {
		return err
	}
	if err := env.RequireBTFType("btf_trace_sys_enter", "BTF-typed raw tracepoints"); err != nil {
		return err
	}
	return env.RequireUserMemoryReads()
}

type objects struct {
	bpfprogPrograms
	bpfprogMaps
}

func (o *objects) Close() {
	o.bpfprogPrograms.Close()
	o.bpfprogMaps.Close()
}

func (*Cell) Run(ctx context.Context, env *core.Env, rec *core.Recorder) error {
	spec, err := loadBpfprog()
	if err != nil {
		return err
	}
	if err := bpfutil.SetTarget(env, spec); err != nil {
		return err
	}
	var objs objects
	if err := bpfutil.Load(env, spec, &objs); err != nil {
		return err
	}
	defer objs.Close()

	tr, err := traceEnumeration(&objs)
	if err != nil {
		return err
	}
	defer tr.Close()

	before, err := kernelProgs(&objs)
	if err != nil {
		return err
	}
	enumerated, err := bpfutil.EnumerateProgIDs()
	if err != nil {
		return err
	}
	after, err := kernelProgs(&objs)
	if err != nil {
		return err
	}
	pinned := pinnedProgs(rec)

	enumSet := make(map[uint32]bool, len(enumerated))
	for _, id := range enumerated {
		enumSet[id] = true
	}

	// Canary: our own iterator program must show up in both views.
	selfID, err := bpfutil.ProgramID(objs.DumpBpfProg)
	if err != nil {
		return err
	}
	name := fmt.Sprintf("program #%d", selfID)
	_, inKernel := before[selfID]
	rec.Canary(name, "BPF program iterator", inKernel)
	rec.Canary(name, "BPF_PROG_GET_NEXT_ID enumeration", enumSet[selfID])

	// Present in both kernel snapshots but never enumerated.
	stable := make(map[uint32]bpfprogProgInfo)
	for id, p := range before {
		if _, ok := after[id]; ok {
			stable[id] = p
		}
	}
	hidden := 0
	for id, p := range stable {
		if enumSet[id] {
			continue
		}
		hidden++
		details := map[string]string{
			"program_id":   strconv.Itoa(int(id)),
			"program_name": bpfutil.Int8String(p.Name[:]),
			"program_type": ebpf.ProgramType(p.Type).String(),
		}
		if path, ok := pinned[id]; ok {
			details["pinned_path"] = path
		}
		rec.Suspicious(fmt.Sprintf("BPF program #%d (%s) is loaded but hidden from BPF_PROG_GET_NEXT_ID", id, details["program_name"]), details)
	}

	events, err := tr.drain()
	if err != nil {
		return err
	}
	// Each GET_NEXT_ID call we made, including the final -ENOENT, must be traced.
	rec.Canary(fmt.Sprintf("zygarde's %d BPF_PROG_GET_NEXT_ID calls", len(enumerated)+1),
		"raw sys_enter/sys_exit tracepoints", len(events) >= len(enumerated)+1)
	checkEvents(rec, events, enumerated, stable)

	// Audit what every program (hidden or not) is able to do.
	auditHelpers(rec, env, stable, selfID)

	if hidden > 0 {
		rec.Message("%d BPF program(s) hidden from enumeration (kernel: %d, enumerated: %d, pinned: %d)",
			hidden, len(before), len(enumerated), len(pinned))
	} else {
		rec.Message("No hidden BPF programs (kernel: %d, enumerated: %d, pinned: %d)",
			len(before), len(enumerated), len(pinned))
	}
	return nil
}

// tracer records zygarde's own BPF_PROG_GET_NEXT_ID calls at syscall exit.
type tracer struct {
	links []link.Link
	rd    *ringbuf.Reader
}

// traceEnumeration attaches the raw sys_enter/sys_exit tracepoints.
func traceEnumeration(objs *objects) (*tracer, error) {
	t := &tracer{}
	for _, tp := range []struct {
		name string
		prog *ebpf.Program
	}{
		{"tp_btf/sys_enter", objs.BpfEnter},
		{"tp_btf/sys_exit", objs.BpfExit},
	} {
		l, err := link.AttachTracing(link.TracingOptions{Program: tp.prog})
		if err != nil {
			t.Close()
			return nil, core.WrapBPF("attach "+tp.name, err)
		}
		t.links = append(t.links, l)
	}
	rd, err := ringbuf.NewReader(objs.EnumEvents)
	if err != nil {
		t.Close()
		return nil, core.WrapBPF("open ring buffer", err)
	}
	t.rd = rd
	return t, nil
}

// Close detaches the tracepoints and closes the reader.
func (t *tracer) Close() {
	for _, l := range t.links {
		l.Close()
	}
	t.links = nil
	if t.rd != nil {
		t.rd.Close()
	}
}

// drain detaches the tracepoints and returns every event recorded so far.
func (t *tracer) drain() ([]bpfprogEnumEvent, error) {
	for _, l := range t.links {
		l.Close()
	}
	t.links = nil

	var events []bpfprogEnumEvent
	t.rd.SetDeadline(time.Now())
	for {
		record, err := t.rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return events, nil
		}
		if err != nil {
			return events, fmt.Errorf("reading ring buffer: %w", err)
		}
		ev, err := bpfutil.Decode[bpfprogEnumEvent](record.RawSample)
		if err != nil || len(ev) != 1 {
			return events, fmt.Errorf("decoding enumeration event: %v", err)
		}
		events = append(events, ev[0])
	}
}

// checkEvents compares what the kernel returned at syscall exit with what
// zygarde received.
func checkEvents(rec *core.Recorder, events []bpfprogEnumEvent, enumerated []uint32, stable map[uint32]bpfprogProgInfo) {
	// What userspace received: start_id -> next_id.
	received := make(map[uint32]uint32, len(enumerated))
	prev := uint32(0)
	for _, id := range enumerated {
		received[prev] = id
		prev = id
	}

	for _, ev := range events {
		switch {
		case ev.Ret == -int32(unix.ENOENT):
			var remaining []string
			for id := range stable {
				if id > ev.StartId {
					remaining = append(remaining, strconv.Itoa(int(id)))
				}
			}
			if len(remaining) > 0 {
				rec.Suspicious(fmt.Sprintf("bpf(BPF_PROG_GET_NEXT_ID, start_id=%d) returned -ENOENT although %d program(s) with higher IDs exist", ev.StartId, len(remaining)),
					map[string]string{
						"start_id":        strconv.Itoa(int(ev.StartId)),
						"existing_higher": fmt.Sprint(remaining),
						"technique":       "enumeration cut short with a fake -ENOENT",
					})
			}
		case ev.Ret == 0:
			if got, ok := received[ev.StartId]; ok && got != ev.NextId {
				rec.Suspicious(fmt.Sprintf("bpf(BPF_PROG_GET_NEXT_ID, start_id=%d) returned ID %d at syscall exit but zygarde received %d", ev.StartId, ev.NextId, got),
					map[string]string{
						"start_id":       strconv.Itoa(int(ev.StartId)),
						"kernel_next_id": strconv.Itoa(int(ev.NextId)),
						"received":       strconv.Itoa(int(got)),
						"technique":      "syscall result rewritten in userspace memory",
					})
			}
		}
	}
}

func kernelProgs(objs *objects) (map[uint32]bpfprogProgInfo, error) {
	data, err := bpfutil.ReadIter(objs.DumpBpfProg)
	if err != nil {
		return nil, err
	}
	progs, err := bpfutil.Decode[bpfprogProgInfo](data)
	if err != nil {
		return nil, err
	}
	out := make(map[uint32]bpfprogProgInfo, len(progs))
	for _, p := range progs {
		out[p.Id] = p
	}
	return out, nil
}

// pinnedProgs maps program IDs to the paths they are pinned at.
func pinnedProgs(rec *core.Recorder) map[uint32]string {
	pinned := make(map[uint32]string)
	_ = filepath.WalkDir("/sys/fs/bpf", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		prog, err := ebpf.LoadPinnedProgram(path, nil)
		if err != nil {
			return nil // not a program (map, link...) or unreadable
		}
		defer prog.Close()
		if id, err := bpfutil.ProgramID(prog); err == nil {
			pinned[id] = path
		} else {
			rec.Log().Debug("pinned program has no ID", "path", path, "err", err)
		}
		return nil
	})
	return pinned
}
