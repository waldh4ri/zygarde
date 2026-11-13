package kmodule

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/kattr"
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

// loaderArea is a module-loader allocation.
type loaderArea struct {
	Start, End uint64
}

// orphanLoaderAreas returns the module-loader allocations that contain no
// address of any listed module: neither its base in /proc/modules nor the
// start of one of its ELF sections. Such memory was mapped by the module
// loader for a module that has since removed itself from /proc/modules and
// /sys/module, the two views a rootkit's hide routine edits.
func orphanLoaderAreas(areas []kattr.Area, mods []kattr.ModuleInfo, sections map[string]map[string]uint64) (orphans []loaderArea, considered int) {
	var anchors []uint64
	for _, m := range mods {
		if m.Base != 0 {
			anchors = append(anchors, m.Base)
		}
	}
	for _, secs := range sections {
		for _, a := range secs {
			anchors = append(anchors, a)
		}
	}
	sort.Slice(anchors, func(i, j int) bool { return anchors[i] < anchors[j] })
	owned := func(a kattr.Area) bool {
		i := sort.Search(len(anchors), func(i int) bool { return anchors[i] >= a.Start })
		return i < len(anchors) && anchors[i] < a.End
	}
	for _, a := range areas {
		if !loaderCallers[a.Caller] {
			continue
		}
		considered++
		if !owned(a) {
			orphans = append(orphans, loaderArea{a.Start, a.End})
		}
	}
	return orphans, considered
}

// readLoaderView reads the module views once.
func (c *Cell) readLoaderView() (loaderView, error) {
	var v loaderView
	raw, err := os.ReadFile(c.procModules)
	if err != nil {
		return v, err
	}
	mods, err := kattr.ParseModules(bytes.NewReader(raw))
	if err != nil {
		return v, err
	}
	v.listed = len(mods)
	visible := make(map[string]bool, len(mods))
	based := 0
	for _, m := range mods {
		visible[m.Name] = true
		if m.Base != 0 {
			based++
		}
	}
	if len(mods) > 0 && based == 0 {
		return v, fmt.Errorf("module addresses in %s are hidden (kernel.kptr_restrict)", c.procModules)
	}
	vm, err := os.Open(c.vmallocInfo)
	if err != nil {
		return v, err
	}
	areas, err := kattr.ParseVmallocinfo(vm)
	vm.Close()
	if err != nil {
		// Hashed or hidden addresses: compare counts instead.
		n, cerr := countLoaderAreas(c.vmallocInfo)
		if cerr != nil {
			return v, cerr
		}
		v.areas, v.byCount = n, true
		return v, nil
	}
	// Only modules listed in /proc/modules are read: the section files of a
	// module a rootkit unlinked can be freed memory (see kattr.ReadSections).
	v.orphans, v.areas = orphanLoaderAreas(areas, mods, kattr.ReadSections(c.sysModule, visible))
	return v, nil
}

// checkLoaderAllocations reports module-loader memory that no listed module
// owns. It returns the number of findings.
func (c *Cell) checkLoaderAllocations(rec *core.Recorder) int {
	v, err := c.readLoaderView()
	if err != nil {
		rec.Limit("Module memory in /proc/vmallocinfo was not compared with /proc/modules: %v", err)
		return 0
	}
	if v.areas == 0 {
		rec.Limit("Module memory in /proc/vmallocinfo was not compared with /proc/modules: this kernel shows no per-module allocations")
		return 0
	}
	if v.byCount && !onePerModule(c.release) {
		rec.Limit("Module memory in /proc/vmallocinfo was not compared with /proc/modules: kernel %s gives each module several allocations and prints hashed addresses", c.release)
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

	if v.byCount || again.byCount {
		n := min(v.excess(), again.excess())
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("%d module-loader allocation(s) in /proc/vmallocinfo belong to no module (%d allocations, %d modules listed in /proc/modules)", n, again.areas, again.listed),
			Details: map[string]string{
				"allocations": fmt.Sprintf("%d", again.areas),
				"modules":     fmt.Sprintf("%d", again.listed),
				"unexplained": fmt.Sprintf("%d", n),
				"method":      "count (this kernel prints hashed addresses in /proc/vmallocinfo)",
			},
			Why:    loaderWhy,
			Benign: "A module loading or unloading while the scan ran is excluded by a second read 300 ms later.",
		})
		return 1
	}

	still := map[loaderArea]bool{}
	for _, a := range again.orphans {
		still[a] = true
	}
	found := 0
	for _, a := range v.orphans {
		if !still[a] {
			continue
		}
		found++
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("Kernel memory mapped by the module loader at %#x-%#x belongs to no module listed in /proc/modules", a.Start, a.End),
			Details: map[string]string{
				"address": fmt.Sprintf("%#x", a.Start),
				"size":    fmt.Sprintf("%d", a.End-a.Start),
				"modules": fmt.Sprintf("%d", again.listed),
				"method":  "address ownership",
			},
			Why:    loaderWhy,
			Benign: "A module loading or unloading while the scan ran is excluded by a second read 300 ms later.",
		})
	}
	return found
}

const loaderWhy = "Every loaded module owns an allocation made by the kernel's module loader, which /proc/vmallocinfo lists " +
	"with the allocator's name. This one matches no module in /proc/modules. A rootkit module that removed itself from " +
	"the module list and from /sys/module (so the two views agree) still leaves its memory mapped. Kernel taint flags " +
	"that no listed module explains point the same way."

// countLoaderAreas counts the vmallocinfo allocations made by the module
// loader. It needs no addresses, so it works where /proc/vmallocinfo prints
// hashed pointers (kernels that format it with %pK, such as 5.10).
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

// loaderView is what one read of the module views shows.
type loaderView struct {
	orphans []loaderArea // set when addresses are real
	areas   int          // module-loader allocations
	listed  int          // modules in /proc/modules
	byCount bool         // addresses hashed: only the counts are comparable
}

// excess is how many module-loader allocations no listed module accounts for.
func (v loaderView) excess() int {
	if v.byCount {
		if d := v.areas - v.listed; d > 0 {
			return d
		}
		return 0
	}
	return len(v.orphans)
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
