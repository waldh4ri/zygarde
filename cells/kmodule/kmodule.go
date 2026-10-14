// Package kmodule detects loadable kernel modules hidden from one of the
// kernel's two module views.
package kmodule

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/waldh4ri/zygarde/internal/core"
)

// Cell compares /proc/modules with /sys/module.
//
// /proc/modules walks the kernel's module list; /sys/module comes from each
// module's kobject. Rootkits commonly unlink themselves from the list
// (list_del) or delete their kobject (kobject_del), which makes the two views
// disagree.
//
// /sys/module also contains built-in modules. Only loadable modules get the
// "initstate" attribute (kernel/module/sysfs.c), which tells them apart.
//
// It does not use eBPF: there is no module iterator, and the ksym iterator
// walks the same list as /proc/modules.
type Cell struct {
	procModules string
	sysModule   string
	sysBTF      string
}

// New returns the hidden kernel module Cell.
func New() *Cell {
	return &Cell{procModules: "/proc/modules", sysModule: "/sys/module", sysBTF: "/sys/kernel/btf"}
}

func (*Cell) ID() string                    { return "hidden_kernel_module" }
func (*Cell) Name() string                  { return "Hidden Kernel Module Detection" }
func (*Cell) Timeout() time.Duration        { return 15 * time.Second }
func (*Cell) Supported(env *core.Env) error { return nil }
func (*Cell) Description() string {
	return "Compares the module list (/proc/modules) with module kobjects (/sys/module) and module BTF (/sys/kernel/btf)"
}

// views are three independent records of the loaded modules.
type views struct {
	proc map[string]bool // the module list
	sys  map[string]bool // module kobjects of loadable modules
	btf  map[string]bool // module BTF, registered on its own list (btf_modules)
}

// hidden is a module missing from one view, with how it is hidden.
type hidden struct {
	module, desc, technique string
}

func (v views) hidden() []hidden {
	var out []hidden
	notInProc, notInSys := Compare(v.proc, v.sys)
	for _, m := range notInProc {
		out = append(out, hidden{m, fmt.Sprintf("Module %s is loaded (in /sys/module) but hidden from /proc/modules and lsmod", m),
			"removed from the kernel module list (list_del)"})
	}
	for _, m := range notInSys {
		out = append(out, hidden{m, fmt.Sprintf("Module %s is in /proc/modules but has no /sys/module entry", m),
			"module kobject removed (kobject_del)"})
	}
	// Module BTF is kept on its own list and survives list_del. Only report
	// modules not already caught through /sys/module.
	for m := range v.btf {
		if !v.proc[m] && !v.sys[m] {
			out = append(out, hidden{m, fmt.Sprintf("Module %s has kernel BTF (/sys/kernel/btf/%s) but is hidden from /proc/modules and /sys/module", m, m),
				"removed from the module list and sysfs; its BTF registration remains"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].desc < out[j].desc })
	return out
}

func (c *Cell) Run(ctx context.Context, env *core.Env, rec *core.Recorder) error {
	v, err := c.snapshot()
	if err != nil {
		return err
	}
	found := v.hidden()

	// Re-check with a fresh snapshot so modules loading or unloading
	// mid-scan aren't reported.
	if len(found) > 0 {
		v2, err := c.snapshot()
		if err != nil {
			return err
		}
		again := map[string]bool{}
		for _, h := range v2.hidden() {
			again[h.desc] = true
		}
		var confirmed []hidden
		for _, h := range found {
			if again[h.desc] {
				confirmed = append(confirmed, h)
			}
		}
		found = confirmed
	}

	for _, h := range found {
		rec.Suspicious(h.desc, map[string]string{"module": h.module, "technique": h.technique})
	}
	if len(found) > 0 {
		rec.Message("%d hidden kernel module(s)", len(found))
	} else {
		rec.Message("All %d loaded modules are consistent across /proc/modules, /sys/module and module BTF", len(v.proc))
	}
	return nil
}

func (c *Cell) snapshot() (views, error) {
	var v views
	f, err := os.Open(c.procModules)
	if err != nil {
		return v, err
	}
	defer f.Close()
	if v.proc, err = ParseProcModules(f); err != nil {
		return v, fmt.Errorf("reading %s: %w", c.procModules, err)
	}
	if v.sys, err = loadableSysModules(c.sysModule); err != nil {
		return v, err
	}
	v.btf = btfModules(c.sysBTF)
	return v, nil
}

// btfModules lists module BTF files (everything but vmlinux). It returns an
// empty set on kernels without module BTF.
func btfModules(root string) map[string]bool {
	mods := make(map[string]bool)
	entries, err := os.ReadDir(root)
	if err != nil {
		return mods
	}
	for _, e := range entries {
		if e.Name() != "vmlinux" {
			mods[e.Name()] = true
		}
	}
	return mods
}

// ParseProcModules returns the module names in /proc/modules content.
func ParseProcModules(r io.Reader) (map[string]bool, error) {
	mods := make(map[string]bool)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if name, _, ok := strings.Cut(sc.Text(), " "); ok && name != "" {
			mods[name] = true
		}
	}
	return mods, sc.Err()
}

// loadableSysModules returns /sys/module entries that are loadable modules.
func loadableSysModules(root string) (map[string]bool, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("listing %s: %w", root, err)
	}
	mods := make(map[string]bool)
	for _, e := range entries {
		if _, err := os.Stat(filepath.Join(root, e.Name(), "initstate")); err == nil {
			mods[e.Name()] = true
		}
	}
	return mods, nil
}

// Compare returns loadable modules missing from /proc/modules and modules
// from /proc/modules missing from /sys/module.
func Compare(proc, sys map[string]bool) (notInProc, notInSys []string) {
	for m := range sys {
		if !proc[m] {
			notInProc = append(notInProc, m)
		}
	}
	for m := range proc {
		if !sys[m] {
			notInSys = append(notInSys, m)
		}
	}
	return notInProc, notInSys
}
