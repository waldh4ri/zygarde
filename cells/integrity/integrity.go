// Package integrity checks that bpf() itself works honestly for Zygarde
// before the other Cells rely on it.
package integrity

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/core"
)

// Cell loads a trivial program and map, then checks that the kernel lets us
// load them and that userspace enumeration lists them.
type Cell struct{}

// New returns the eBPF integrity Cell.
func New() *Cell { return &Cell{} }

func (*Cell) ID() string             { return "ebpf_integrity" }
func (*Cell) Name() string           { return "eBPF Integrity" }
func (*Cell) Timeout() time.Duration { return 15 * time.Second }
func (*Cell) Description() string {
	return "Checks that bpf() is not blocked or filtered for the scanner by loading canary objects and looking for them"
}

func (*Cell) Supported(env *core.Env) error {
	// A seccomp filter doesn't necessarily block bpf(), so only missing
	// privileges skip this Cell; Classify won't call denials suspicious then.
	if !env.Privileged() {
		return core.Skip("process lacks CAP_BPF/CAP_SYS_ADMIN")
	}
	return nil
}

func (*Cell) Run(ctx context.Context, env *core.Env, rec *core.Recorder) error {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "zyg_canary",
		Type: ebpf.SocketFilter,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "Dual BSD/GPL",
	})
	if err != nil {
		return core.WrapBPF("load canary program", err)
	}
	defer prog.Close()

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "zyg_canary",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		return core.WrapBPF("create canary map", err)
	}
	defer m.Close()

	progID, err := bpfutil.ProgramID(prog)
	if err != nil {
		return err
	}
	mapInfo, err := m.Info()
	if err != nil {
		return core.WrapBPF("BPF_OBJ_GET_INFO_BY_FD (map)", err)
	}
	mapID, ok := mapInfo.ID()
	if !ok {
		return fmt.Errorf("kernel did not report a map ID")
	}

	progIDs, err := bpfutil.EnumerateProgIDs()
	if err != nil {
		return err
	}
	mapIDs, err := bpfutil.EnumerateMapIDs()
	if err != nil {
		return err
	}

	progName := fmt.Sprintf("program #%d", progID)
	mapName := fmt.Sprintf("map #%d", mapID)
	rec.Canary(progName, "BPF_PROG_GET_NEXT_ID enumeration", slices.Contains(progIDs, progID))
	rec.Canary(mapName, "BPF_MAP_GET_NEXT_ID enumeration", slices.Contains(mapIDs, uint32(mapID)))

	byID, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID))
	rec.Canary(progName, "BPF_PROG_GET_FD_BY_ID", err == nil)
	if err == nil {
		byID.Close()
	}

	rec.Message("bpf() works normally (%d programs, %d maps enumerated)", len(progIDs), len(mapIDs))
	return nil
}
