package kmodule

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/waldh4ri/zygarde/internal/core"
)

// loaderCallers are the functions /proc/vmallocinfo names as the allocator of a
// module's memory. Which one appears depends on the kernel and on inlining:
// load_module (Debian 5.10), layout_and_allocate (5.4, RHEL 8), move_module
// (5.15 and later). Up to Linux 6.3 each module owns one such allocation. From
// 6.4 a module has one per memory type (text, data, rodata...) and 7.0 carves
// them out of a shared execmem cache, so the counts are not comparable there.
var loaderCallers = map[string]bool{
	"load_module": true, "move_module": true, "layout_and_allocate": true, "module_alloc": true,
}

// countLoaderAreas counts the vmallocinfo allocations made by the module
// loader. It needs no addresses, which most kernels print hashed here even
// with kptr_restrict=0.
func countLoaderAreas(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		f := bytes.Fields(line)
		if len(f) < 3 {
			continue
		}
		caller, _, _ := bytes.Cut(f[2], []byte{'+'})
		if loaderCallers[string(caller)] {
			n++
		}
	}
	return n, nil
}

// countModules counts the modules listed in /proc/modules.
func countModules(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		if len(bytes.Fields(line)) >= 6 {
			n++
		}
	}
	return n, nil
}

// loaderView is what one read of the module views shows.
type loaderView struct {
	areas  int // module-loader allocations in /proc/vmallocinfo
	listed int // modules in /proc/modules
}

// excess is how many module-loader allocations no listed module accounts for.
func (v loaderView) excess() int {
	if d := v.areas - v.listed; d > 0 {
		return d
	}
	return 0
}

func (c *Cell) readLoaderView() (loaderView, error) {
	var v loaderView
	var err error
	if v.listed, err = countModules(c.procModules); err != nil {
		return v, err
	}
	v.areas, err = countLoaderAreas(c.vmallocInfo)
	return v, err
}

// checkLoaderAllocations reports module-loader memory that no listed module
// accounts for: more allocations than listed modules, still true 300 ms later.
// It returns the number of findings.
//
// It deliberately reads only /proc/modules and /proc/vmallocinfo. A module's
// sysfs section files are backed by memory a rootkit can free while leaving
// the files behind, and reading them oopses the kernel.
func (c *Cell) checkLoaderAllocations(rec *core.Recorder) int {
	if !onePerModule(c.release) {
		rec.Limit("Module memory in /proc/vmallocinfo was not compared with /proc/modules: kernel %s gives each module several allocations or carves them from a shared cache", c.release)
		return 0
	}
	v, err := c.readLoaderView()
	if err != nil {
		rec.Limit("Module memory in /proc/vmallocinfo was not compared with /proc/modules: %v", err)
		return 0
	}
	if v.areas == 0 {
		rec.Limit("Module memory in /proc/vmallocinfo was not compared with /proc/modules: this kernel shows no per-module allocations")
		return 0
	}
	if v.excess() == 0 {
		return 0
	}
	// A module still loading or unloading shows up for an instant: keep only
	// what is still unexplained in a second read.
	time.Sleep(300 * time.Millisecond)
	again, err := c.readLoaderView()
	if err != nil || again.excess() == 0 {
		return 0
	}
	n := min(v.excess(), again.excess())
	rec.Suspicious(core.Finding{
		Description: fmt.Sprintf("%d module-loader allocation(s) in /proc/vmallocinfo belong to no module (%d allocations, %d modules listed in /proc/modules)", n, again.areas, again.listed),
		Details: map[string]string{
			"allocations": fmt.Sprintf("%d", again.areas),
			"modules":     fmt.Sprintf("%d", again.listed),
			"unexplained": fmt.Sprintf("%d", n),
		},
		Why: "Every loaded module owns an allocation made by the kernel's module loader, which /proc/vmallocinfo lists " +
			"with the allocator's name. This one matches no module in /proc/modules. A rootkit module that removed itself from " +
			"the module list and from /sys/module (so the two views agree) still leaves its memory mapped. Kernel taint flags " +
			"that no listed module explains point the same way.",
		Benign: "A module loading or unloading while the scan ran is excluded by a second read 300 ms later.",
	})
	return 1
}

// onePerModule reports whether the kernel release gives every module exactly
// one module-loader allocation (before Linux 6.4), which the count comparison
// relies on. Unparseable releases are treated as new.
func onePerModule(release string) bool {
	var major, minor int
	if n, _ := fmt.Sscanf(release, "%d.%d", &major, &minor); n != 2 {
		return false
	}
	return major < 6 || (major == 6 && minor < 4)
}
