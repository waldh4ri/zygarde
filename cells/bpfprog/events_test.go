package bpfprog

import (
	"io"
	"log/slog"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/core"
)

func findings(events []bpfprogEnumEvent, enumerated []uint32, stable []uint32) int {
	rec := core.NewRecorder(slog.New(slog.NewTextHandler(io.Discard, nil)))
	progs := make(map[uint32]bpfprogProgInfo)
	for _, id := range stable {
		progs[id] = bpfprogProgInfo{Id: id}
	}
	checkEvents(rec, events, enumerated, progs)
	return len(rec.Findings())
}

func TestCheckEventsClean(t *testing.T) {
	events := []bpfprogEnumEvent{
		{StartId: 0, Ret: 0, NextId: 3},
		{StartId: 3, Ret: 0, NextId: 7},
		{StartId: 7, Ret: -int32(unix.ENOENT)},
	}
	if n := findings(events, []uint32{3, 7}, []uint32{3, 7}); n != 0 {
		t.Errorf("clean enumeration produced %d findings", n)
	}
}

func TestCheckEventsFakeENOENT(t *testing.T) {
	// Program 9 exists but enumeration was cut short after 3.
	events := []bpfprogEnumEvent{
		{StartId: 0, Ret: 0, NextId: 3},
		{StartId: 3, Ret: -int32(unix.ENOENT)},
	}
	if n := findings(events, []uint32{3}, []uint32{3, 9}); n != 1 {
		t.Errorf("fake ENOENT: got %d findings, want 1", n)
	}
}

func TestCheckEventsRewrittenResult(t *testing.T) {
	// The kernel answered 5 but zygarde received 7: 5 was skipped over.
	events := []bpfprogEnumEvent{
		{StartId: 0, Ret: 0, NextId: 3},
		{StartId: 3, Ret: 0, NextId: 5},
		{StartId: 7, Ret: -int32(unix.ENOENT)},
	}
	if n := findings(events, []uint32{3, 7}, []uint32{3, 5, 7}); n != 1 {
		t.Errorf("rewritten result: got %d findings, want 1", n)
	}
}
