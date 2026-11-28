// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package ktask

import (
	"fmt"
	"os"
	"strconv"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/kmem"
)

// ForceEnv set to "memory" makes Cells use the memory views even where BPF
// iterators exist, to compare both.
const ForceEnv = "ZYGARDE_TASK_VIEW"

// Use reports whether a Cell should read kernel memory instead of using the
// BPF iterator whose context type is iterType ("bpf_iter__task"...).
func Use(env *core.Env, iterType string) bool {
	return os.Getenv(ForceEnv) == "memory" || !core.HasBTFType(env.BTF, iterType)
}

// Supported says whether the memory views can run: they need BTF (for the
// offsets) and the initial PID namespace (they read init-namespace IDs,
// which /proc then shows). init_task is found from zygarde's own task, so
// no kernel symbols are needed.
func Supported(env *core.Env, what string) error {
	if err := env.RequireBTF(); err != nil {
		return err
	}
	if _, err := NewLayout(env.BTF); err != nil {
		return core.Skip("the kernel's BTF lacks task fields the memory view needs: %v", err)
	}
	if init, err := bpfutil.InInitPIDNS(); err != nil || !init {
		return core.Skip("no %s, and the kernel memory view needs the initial PID namespace", what)
	}
	if env.Lockdown == "confidentiality" {
		return core.Skip("kernel lockdown (confidentiality)")
	}
	return nil
}

// Source reads task snapshots from kernel memory.
type Source struct {
	Mem      *kmem.Reader
	Layout   Layout
	InitTask uint64
}

// Open loads the memory reader and finds init_task, the root of zygarde's
// own real_parent chain. rec, if set, gets the reader's program ID.
func Open(env *core.Env, rec *core.Recorder) (*Source, error) {
	layout, err := NewLayout(env.BTF)
	if err != nil {
		return nil, err
	}
	mem, err := kmem.Open(env)
	if err != nil {
		return nil, err
	}
	if id := mem.ProgramID(); id != 0 && rec != nil {
		rec.Footprint("bpf_prog_id", strconv.FormatUint(uint64(id), 10))
	}
	self, err := mem.CurrentTask()
	if err == nil {
		var initTask uint64
		if initTask, err = FindInitTask(mem, layout, self); err == nil {
			return &Source{Mem: mem, Layout: layout, InitTask: initTask}, nil
		}
	}
	mem.Close()
	return nil, fmt.Errorf("finding init_task: %w", err)
}

// Snapshot reads the kernel's tasks.
func (s *Source) Snapshot() (*View, error) { return Snapshot(s.Mem, s.Layout, s.InitTask) }

// Close releases the memory reader.
func (s *Source) Close() { s.Mem.Close() }

// Processes returns the thread group leaders of a view, for walks that need
// one task per process.
func (v *View) Processes() []*Task {
	var out []*Task
	for _, t := range v.Tasks {
		if t.Addr == t.Leader && t.PID != 0 {
			out = append(out, t)
		}
	}
	return out
}
