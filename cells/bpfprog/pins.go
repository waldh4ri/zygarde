package bpfprog

import (
	"io/fs"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/waldh4ri/zygarde/internal/fdowner"
)

// pin is an object pinned in a BPF filesystem.
type pin struct {
	Path   string
	Kind   fdowner.Kind
	ID     uint32
	Name   string // programs and maps
	ProgID uint32 // links: the program they run
}

// bpffsRoot is where BPF filesystems are conventionally mounted.
const bpffsRoot = "/sys/fs/bpf"

// pins lists every program, map and link pinned under /sys/fs/bpf.
func pins() []pin {
	var out []pin
	_ = filepath.WalkDir(bpffsRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		// Programs and links can only be opened read-write; maps read-only.
		if p, err := ebpf.LoadPinnedProgram(path, nil); err == nil {
			defer p.Close()
			if info, err := p.Info(); err == nil {
				id, _ := info.ID()
				out = append(out, pin{Path: path, Kind: fdowner.Prog, ID: uint32(id), Name: info.Name})
			}
			return nil
		}
		if m, err := ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{ReadOnly: true}); err == nil {
			defer m.Close()
			if info, err := m.Info(); err == nil {
				id, _ := info.ID()
				out = append(out, pin{Path: path, Kind: fdowner.Map, ID: uint32(id), Name: info.Name})
			}
			return nil
		}
		if l, err := link.LoadPinnedLink(path, nil); err == nil {
			defer l.Close()
			if info, err := l.Info(); err == nil {
				out = append(out, pin{Path: path, Kind: fdowner.Link, ID: uint32(info.ID), ProgID: uint32(info.Program)})
			}
		}
		return nil
	})
	return out
}

// pinnedProgs maps program IDs to a path that keeps them loaded: the program
// itself or a link running it.
func pinnedProgs(ps []pin) map[uint32]string {
	out := map[uint32]string{}
	for _, p := range ps {
		switch p.Kind {
		case fdowner.Prog:
			out[p.ID] = p.Path
		case fdowner.Link:
			if _, ok := out[p.ProgID]; !ok {
				out[p.ProgID] = p.Path
			}
		}
	}
	return out
}
