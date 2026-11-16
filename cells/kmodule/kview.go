package kmodule

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf/btf"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/kmem"
)

// Kernel views of struct module, read from kernel memory (internal/kmem):
//
//   - the module list (the "modules" symbol), which /proc/modules prints;
//   - module_kset, the kobjects behind /sys/module, each pointing back to its
//     struct module;
//   - mod_tree, the latched rbtree the kernel searches to map an address to
//     its module (__module_address: exception tables, kallsyms, stack
//     traces). A module that unlinks itself from the list and deletes its
//     kobject still sits there.
//
// Every struct module found is also checked for section attributes freed
// behind the sysfs files that still point at them (Diamorphine): reading
// those files oopses the kernel, so only the directory listing is compared.

// MODULE_STATE_LIVE: a module neither loading nor unloading.
const moduleStateLive = 0

const (
	maxModules  = 8192    // list, kset and tree walk bounds
	maxTreeNode = 1 << 16 // mod_tree nodes: one per module memory type
	maxSections = 2048
)

// modLayout holds the offsets the walks use, from the running kernel's BTF.
type modLayout struct {
	list, name, nameLen, state uint64 // struct module
	sectAttrs, notesAttrs      uint64
	hasSect, hasNotes          bool
	kobjEntry                  uint64 // struct kobject
	kobjToMod                  uint64 // module_kobject.mod minus module_kobject.kobj
	ksetList                   uint64 // struct kset
	hasTree                    bool
	treeRoots                  uint64 // mod_tree_root.root.tree
	mtnMod, mtnNode, rbNode    uint64 // mod_tree_node.mod, .node.node, sizeof(rb_node)
	rbRight, rbLeft            uint64
	grpName, grpAttrs          uint64 // module_sect_attrs.grp.{name,attrs}
	grpBinAttrs                uint64
	hasBinAttrs                bool
	attrName                   uint64 // struct attribute.name
}

func newModLayout(spec *btf.Spec) (modLayout, error) {
	var l modLayout
	get := func(typ, path string, dst *uint64) error {
		f, err := kmem.Lookup(spec, typ, path)
		if err == nil {
			*dst = f.Offset
		}
		return err
	}
	name, err := kmem.Lookup(spec, "module", "name")
	if err != nil {
		return l, err
	}
	l.name, l.nameLen = name.Offset, name.Size
	var kobj, mod uint64
	for _, f := range []struct {
		typ, path string
		dst       *uint64
	}{
		{"module", "list", &l.list},
		{"module", "state", &l.state},
		{"module_kobject", "kobj", &kobj},
		{"module_kobject", "mod", &mod},
		{"kobject", "entry", &l.kobjEntry},
		{"kset", "list", &l.ksetList},
		{"attribute", "name", &l.attrName},
	} {
		if err := get(f.typ, f.path, f.dst); err != nil {
			return l, err
		}
	}
	l.kobjToMod = mod - kobj
	l.hasSect = get("module", "sect_attrs", &l.sectAttrs) == nil &&
		get("module_sect_attrs", "grp.name", &l.grpName) == nil &&
		get("module_sect_attrs", "grp.attrs", &l.grpAttrs) == nil
	if l.hasSect {
		l.hasBinAttrs = get("module_sect_attrs", "grp.bin_attrs", &l.grpBinAttrs) == nil ||
			get("module_sect_attrs", "grp.bin_attrs_new", &l.grpBinAttrs) == nil
	}
	l.hasNotes = get("module", "notes_attrs", &l.notesAttrs) == nil
	// mod_tree exists with CONFIG_MODULES_TREE_LOOKUP (perf events or tracing).
	rb, err := kmem.Size(spec, "rb_node")
	l.rbNode = rb
	l.hasTree = err == nil &&
		get("mod_tree_root", "root.tree", &l.treeRoots) == nil &&
		get("mod_tree_node", "mod", &l.mtnMod) == nil &&
		get("mod_tree_node", "node.node", &l.mtnNode) == nil &&
		get("rb_node", "rb_right", &l.rbRight) == nil &&
		get("rb_node", "rb_left", &l.rbLeft) == nil
	return l, nil
}

// modSyms are the kernel variables the walks start from.
type modSyms struct {
	modules, kset, tree uint64 // 0 when unknown
}

// kmod is one struct module found in kernel memory.
type kmod struct {
	addr                   uint64
	name                   string
	state                  uint32
	sectAttrs, notesAttrs  uint64
	inList, inKset, inTree bool
}

// kernelView is what one walk of the kernel's module structures found.
type kernelView struct {
	mods   map[uint64]*kmod
	ksetOK bool
	treeOK bool
	limits []string
}

func (kv *kernelView) mod(addr uint64) *kmod {
	m := kv.mods[addr]
	if m == nil {
		m = &kmod{addr: addr}
		kv.mods[addr] = m
	}
	return m
}

// readKernelView walks the three kernel views and reads each module found.
// visible is the userspace view, used to check that each walk works on this
// kernel: a walk that misses a module /proc/modules or /sys/module shows is
// not trusted.
func readKernelView(mem kmem.Memory, l modLayout, s modSyms, visible views) (kernelView, error) {
	kv := kernelView{mods: map[uint64]*kmod{}}

	var nodes []uint64
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if nodes, err = kmem.WalkList(mem, s.modules, maxModules); !errors.Is(err, kmem.ErrChanged) {
			break
		}
	}
	if err != nil {
		return kv, fmt.Errorf("module list: %w", err)
	}
	for _, n := range nodes {
		kv.mod(n - l.list).inList = true
	}

	if s.kset == 0 {
		kv.limits = append(kv.limits, "module_kset is not in /proc/kallsyms")
	} else if err := walkKset(mem, l, s.kset, &kv); err != nil {
		kv.limits = append(kv.limits, fmt.Sprintf("module_kset: %v", err))
	} else {
		kv.ksetOK = true
	}

	switch {
	case !l.hasTree:
		kv.limits = append(kv.limits, "this kernel has no module address tree (CONFIG_MODULES_TREE_LOOKUP)")
	case s.tree == 0:
		kv.limits = append(kv.limits, "mod_tree is not in /proc/kallsyms")
	default:
		if err := walkTree(mem, l, s.tree, &kv); err != nil {
			kv.limits = append(kv.limits, fmt.Sprintf("mod_tree: %v", err))
		} else {
			kv.treeOK = true
		}
	}

	if err := readModules(mem, l, &kv); err != nil {
		return kv, err
	}
	kv.selfCheck(visible)
	return kv, nil
}

func walkKset(mem kmem.Memory, l modLayout, ksetSym uint64, kv *kernelView) error {
	vals, ok, err := kmem.ReadU64s(mem, []uint64{ksetSym})
	if err != nil {
		return err
	}
	if !ok[0] || vals[0] == 0 {
		return errors.New("not readable")
	}
	var nodes []uint64
	for attempt := 0; attempt < 3; attempt++ {
		if nodes, err = kmem.WalkList(mem, vals[0]+l.ksetList, 4*maxModules); !errors.Is(err, kmem.ErrChanged) {
			break
		}
	}
	if err != nil {
		return err
	}
	addrs := make([]uint64, len(nodes))
	for i, n := range nodes {
		addrs[i] = n - l.kobjEntry + l.kobjToMod
	}
	mods, ok, err := kmem.ReadU64s(mem, addrs)
	if err != nil {
		return err
	}
	for i, m := range mods {
		if ok[i] && m != 0 { // built-in modules with parameters have no struct module
			kv.mod(m).inKset = true
		}
	}
	return nil
}

// walkTree visits both copies of the latched mod_tree breadth-first, one
// batch per level.
func walkTree(mem kmem.Memory, l modLayout, treeSym uint64, kv *kernelView) error {
	for copyIdx := uint64(0); copyIdx < 2; copyIdx++ {
		roots, ok, err := kmem.ReadU64s(mem, []uint64{treeSym + l.treeRoots + 8*copyIdx})
		if err != nil {
			return err
		}
		if !ok[0] {
			return errors.New("not readable")
		}
		// node.node[copyIdx] is the rb_node linked into tree[copyIdx].
		toNode := l.mtnNode + copyIdx*l.rbNode
		seen := map[uint64]bool{}
		frontier := []uint64{}
		if roots[0] != 0 {
			frontier = append(frontier, roots[0])
		}
		for len(frontier) > 0 {
			if len(seen)+len(frontier) > maxTreeNode {
				return fmt.Errorf("more than %d nodes", maxTreeNode)
			}
			var addrs []uint64
			for _, rb := range frontier {
				seen[rb] = true
				addrs = append(addrs, rb+l.rbRight, rb+l.rbLeft, rb-toNode+l.mtnMod)
			}
			vals, ok, err := kmem.ReadU64s(mem, addrs)
			if err != nil {
				return err
			}
			var next []uint64
			for i := range frontier {
				r, lft, m := 3*i, 3*i+1, 3*i+2
				if !ok[r] || !ok[lft] || !ok[m] {
					return fmt.Errorf("node %#x is not readable", frontier[i])
				}
				if vals[m] != 0 {
					kv.mod(vals[m]).inTree = true
				}
				for _, child := range []uint64{vals[r], vals[lft]} {
					if child != 0 && !seen[child] {
						next = append(next, child)
					}
				}
			}
			frontier = next
		}
	}
	return nil
}

// readModules reads name, state and attribute pointers of every module
// found. A pointer that leads to no plausible struct module (a tree read
// while it changed) is dropped.
func readModules(mem kmem.Memory, l modLayout, kv *kernelView) error {
	addrs := make([]uint64, 0, len(kv.mods))
	for a := range kv.mods {
		addrs = append(addrs, a)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i] < addrs[j] })
	const per = 4
	reqs := make([]kmem.Req, 0, per*len(addrs))
	for _, a := range addrs {
		reqs = append(reqs,
			kmem.Req{Addr: a + l.name, Len: int(min(l.nameLen, kmem.ChunkSize))},
			kmem.Req{Addr: a + l.state, Len: 4},
			kmem.Req{Addr: a + l.sectAttrs, Len: 8},
			kmem.Req{Addr: a + l.notesAttrs, Len: 8})
	}
	got, err := mem.Read(reqs)
	if err != nil {
		return err
	}
	for i, a := range addrs {
		m := kv.mods[a]
		name, ok := kmem.String(got[per*i])
		if !ok || name == "" || got[per*i+1] == nil || strings.ContainsAny(name, "/ ") {
			delete(kv.mods, a)
			continue
		}
		m.name, m.state = name, kmem.U32(got[per*i+1])
		if l.hasSect {
			m.sectAttrs = kmem.U64(got[per*i+2])
		}
		if l.hasNotes {
			m.notesAttrs = kmem.U64(got[per*i+3])
		}
	}
	return nil
}

// selfCheck distrusts a kernel view that misses modules userspace sees.
func (kv *kernelView) selfCheck(visible views) {
	inList, inKset, inTree := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, m := range kv.mods {
		if m.inList {
			inList[m.name] = true
		}
		if m.inKset {
			inKset[m.name] = true
		}
		if m.inTree {
			inTree[m.name] = true
		}
	}
	missing := func(want, have map[string]bool) []string {
		var out []string
		for n := range want {
			if !have[n] {
				out = append(out, n)
			}
		}
		sort.Strings(out)
		return out
	}
	if kv.ksetOK {
		if miss := missing(visible.sys, inKset); len(miss) > 0 {
			kv.ksetOK = false
			kv.limits = append(kv.limits, fmt.Sprintf("module_kset walk missed modules in /sys/module (%s)", strings.Join(miss, ", ")))
		}
	}
	if kv.treeOK {
		if miss := missing(inList, inTree); len(miss) > 0 {
			kv.treeOK = false
			kv.limits = append(kv.limits, fmt.Sprintf("mod_tree walk missed modules of the module list (%s)", strings.Join(miss, ", ")))
		}
	}
}

// counts returns how many modules each trusted view holds (0 if distrusted).
func (kv *kernelView) counts() (list, kobjects, tree int) {
	for _, m := range kv.mods {
		if m.inList {
			list++
		}
		if m.inKset && kv.ksetOK {
			kobjects++
		}
		if m.inTree && kv.treeOK {
			tree++
		}
	}
	return list, kobjects, tree
}

// listComplete reports whether the module list walk found every module
// /proc/modules shows; if not, the walk is wrong for this kernel (or a module
// loaded meanwhile) and nothing it found is reported.
func (kv *kernelView) listComplete(visible views) []string {
	inList := map[string]bool{}
	for _, m := range kv.mods {
		if m.inList {
			inList[m.name] = true
		}
	}
	var miss []string
	for n := range visible.proc {
		if !inList[n] {
			miss = append(miss, n)
		}
	}
	sort.Strings(miss)
	return miss
}

// kfinding is a SUSPICIOUS result of the kernel views.
type kfinding struct {
	module, desc, why string
	details           map[string]string
	hidden            bool // a module hidden from the module list
}

// compareViews reports live modules the kernel holds but the module list or
// /proc/modules does not show. Modules in reported were already reported by
// the /proc/modules and /sys/module comparison.
func compareViews(kv kernelView, visible views, reported map[string]bool) []kfinding {
	var out []kfinding
	for _, m := range kv.mods {
		if m.state != moduleStateLive || reported[m.name] {
			continue
		}
		details := map[string]string{
			"module":          m.name,
			"struct_module":   fmt.Sprintf("%#x", m.addr),
			"in_module_list":  strconv.FormatBool(m.inList),
			"in_mod_tree":     strconv.FormatBool(m.inTree && kv.treeOK),
			"in_module_kset":  strconv.FormatBool(m.inKset && kv.ksetOK),
			"in_proc_modules": strconv.FormatBool(visible.proc[m.name]),
			"in_sys_module":   strconv.FormatBool(visible.sys[m.name]),
		}
		switch {
		case !m.inList && ((m.inTree && kv.treeOK) || (m.inKset && kv.ksetOK)):
			var where []string
			if m.inTree && kv.treeOK {
				where = append(where, "its module address tree (mod_tree)")
			}
			if m.inKset && kv.ksetOK {
				where = append(where, "the /sys/module kobject set")
			}
			why := "The kernel lists modules on its module list, which /proc/modules and lsmod print, and finds a module's code " +
				"through its module address tree, which exception handling and stack traces need. This module is in kernel " +
				"memory and live, but unlinked from the list."
			if !visible.sys[m.name] {
				why += " It also deleted its /sys/module entry, so /proc/modules and /sys/module agree and only kernel memory shows it."
			}
			out = append(out, kfinding{m.name,
				fmt.Sprintf("Module %s is in %s but not in the kernel's module list", m.name, strings.Join(where, " and ")),
				why, details, true})
		case m.inList && !visible.proc[m.name]:
			out = append(out, kfinding{m.name,
				fmt.Sprintf("Module %s is in the kernel's module list but /proc/modules does not show it", m.name),
				"/proc/modules prints the kernel's module list. A live module on the list that the file leaves out means its " +
					"output is being filtered (a hooked seq_file function), which hides the module from lsmod.",
				details, true})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].desc < out[j].desc })
	return out
}

// checkAttrs compares each live module's section and note attributes in
// kernel memory with its /sys/module/<name>/sections and notes directories.
// Listing those directories reads only sysfs's own nodes; their files are
// never read, since a file backed by freed attributes oopses the kernel.
func checkAttrs(mem kmem.Memory, l modLayout, kv kernelView, sysModule string) ([]kfinding, error) {
	var out []kfinding
	mods := make([]*kmod, 0, len(kv.mods))
	for _, m := range kv.mods {
		if m.state == moduleStateLive && (m.inList || (m.inTree && kv.treeOK)) {
			mods = append(mods, m)
		}
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].name < mods[j].name })
	for _, m := range mods {
		details := map[string]string{"module": m.name, "struct_module": fmt.Sprintf("%#x", m.addr)}
		if l.hasSect {
			dir := filepath.Join(sysModule, m.name, "sections")
			files, err := listNames(dir)
			if err == nil && len(files) > 0 {
				problem, err := checkSections(mem, l, m.sectAttrs, files)
				if err != nil {
					return nil, err
				}
				if problem != "" {
					d := clone(details)
					d["sysfs_dir"], d["sysfs_files"], d["sect_attrs"] = dir, strconv.Itoa(len(files)), fmt.Sprintf("%#x", m.sectAttrs)
					out = append(out, kfinding{m.name,
						fmt.Sprintf("Module %s's section files in sysfs point to freed memory: %s", m.name, problem),
						"Each loaded module's /sys/module/<name>/sections files are backed by its section attributes in kernel memory. " +
							"A rootkit that frees those attributes to hide its load addresses (Diamorphine does) leaves the files behind; " +
							"reading one then makes the kernel use freed memory and oops. Zygarde only lists the directory.",
						d, false})
				}
			}
		}
		if l.hasNotes && m.notesAttrs == 0 {
			dir := filepath.Join(sysModule, m.name, "notes")
			if files, err := listNames(dir); err == nil && len(files) > 0 {
				d := clone(details)
				d["sysfs_dir"], d["sysfs_files"] = dir, strconv.Itoa(len(files))
				out = append(out, kfinding{m.name,
					fmt.Sprintf("Module %s's note files in sysfs point to freed memory: its notes_attrs is NULL but %s lists %d file(s)", m.name, dir, len(files)),
					"Each loaded module's /sys/module/<name>/notes files are backed by its note attributes in kernel memory. " +
						"A module whose attributes were freed while the files remain was tampered with after loading; reading the files oopses the kernel.",
					d, false})
			}
		}
	}
	return out, nil
}

// checkSections returns why sect_attrs does not back the sysfs files, or "".
func checkSections(mem kmem.Memory, l modLayout, sect uint64, files []string) (string, error) {
	if sect == 0 {
		return fmt.Sprintf("its sect_attrs is NULL but the directory lists %d file(s)", len(files)), nil
	}
	ptrs, ok, err := kmem.ReadU64s(mem, []uint64{sect + l.grpName, sect + l.grpAttrs, sect + l.grpBinAttrs})
	if err != nil {
		return "", err
	}
	if !ok[0] || !ok[1] {
		return fmt.Sprintf("its sect_attrs %#x is not readable", sect), nil
	}
	if name, _, err := kmem.ReadStrings(mem, ptrs[:1], 16); err != nil {
		return "", err
	} else if name[0] != "sections" {
		return fmt.Sprintf("its sect_attrs %#x no longer holds the \"sections\" attribute group", sect), nil
	}
	arr := ptrs[1]
	if l.hasBinAttrs && ok[2] && ptrs[2] != 0 {
		arr = ptrs[2] // bin_attribute sections (Linux 5.8+)
	}
	n := min(len(files)+1, maxSections)
	slots := make([]uint64, n)
	for i := range slots {
		slots[i] = arr + 8*uint64(i)
	}
	attrs, ok, err := kmem.ReadU64s(mem, slots)
	if err != nil {
		return "", err
	}
	var nameAddrs []uint64
	for i, a := range attrs {
		if !ok[i] {
			return fmt.Sprintf("its attribute array %#x is not readable", arr), nil
		}
		if a == 0 {
			break
		}
		nameAddrs = append(nameAddrs, a+l.attrName)
	}
	namePtrs, ok, err := kmem.ReadU64s(mem, nameAddrs)
	if err != nil {
		return "", err
	}
	for i := range ok {
		if !ok[i] {
			return "an attribute of its sect_attrs is not readable", nil
		}
	}
	names, ok, err := kmem.ReadStrings(mem, namePtrs, 128)
	if err != nil {
		return "", err
	}
	kernel := map[string]bool{}
	for i, s := range names {
		if !ok[i] {
			return "a section name in its sect_attrs is not readable", nil
		}
		kernel[s] = true
	}
	inDir := map[string]bool{}
	for _, f := range files {
		inDir[f] = true
	}
	if len(kernel) != len(inDir) {
		return fmt.Sprintf("its sect_attrs names %d section(s) but the directory lists %d", len(kernel), len(inDir)), nil
	}
	for f := range inDir {
		if !kernel[f] {
			return fmt.Sprintf("the directory lists %s, which its sect_attrs does not name", f), nil
		}
	}
	return "", nil
}

func listNames(dir string) ([]string, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Readdirnames(-1)
}

func clone(m map[string]string) map[string]string {
	out := make(map[string]string, len(m)+3)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// kernelResult sums up the kernel-memory comparisons.
type kernelResult struct {
	ran                    bool // the module list was walked and trusted
	listed, kobjects, tree int  // modules found in each view (0: view unavailable)
	hidden                 int  // modules hidden from the module list or /proc/modules
	dangling               int  // modules with sysfs attribute files over freed memory
}

// checkKernelViews runs the kernel-memory comparisons and records their
// findings, confirmed by a second read 300 ms later.
func (c *Cell) checkKernelViews(env *core.Env, rec *core.Recorder, reported map[string]bool) (res kernelResult) {
	limit := func(format string, a ...any) {
		rec.Limit("Kernel memory views of the modules were not compared: "+format, a...)
	}
	if env.BTF == nil {
		limit("kernel BTF unavailable")
		return res
	}
	l, err := newModLayout(env.BTF)
	if err != nil {
		limit("%v", err)
		return res
	}
	ks, err := env.Kallsyms()
	if err != nil {
		limit("%v", err)
		return res
	}
	img, err := ks.Image()
	if err != nil {
		limit("%v", err)
		return res
	}
	if !img.HasData {
		limit("/proc/kallsyms lists no data symbols (CONFIG_KALLSYMS_ALL is off)")
		return res
	}
	var s modSyms
	for _, sym := range []struct {
		name string
		dst  *uint64
	}{{"modules", &s.modules}, {"module_kset", &s.kset}, {"mod_tree", &s.tree}} {
		if a, ok := ks.Addr(sym.name); ok && img.InImage(a, 16) && !img.InText(a, 1) {
			*sym.dst = a
		}
	}
	if s.modules == 0 {
		limit("the modules list head is not in the kernel's data in /proc/kallsyms")
		return res
	}
	r, err := kmem.Open(env)
	if err != nil {
		limit("%v", err)
		return res
	}
	defer r.Close()
	if id := r.ProgramID(); id != 0 {
		rec.Footprint("bpf_prog_id", strconv.FormatUint(uint64(id), 10))
	}

	run := func() ([]kfinding, kernelView, error) {
		visible, err := c.snapshot()
		if err != nil {
			return nil, kernelView{}, err
		}
		kv, err := readKernelView(r, l, s, visible)
		if err != nil {
			return nil, kv, err
		}
		if miss := kv.listComplete(visible); len(miss) > 0 {
			return nil, kv, fmt.Errorf("the module list walk missed modules /proc/modules shows (%s)", strings.Join(miss, ", "))
		}
		found := compareViews(kv, visible, reported)
		attrs, err := checkAttrs(r, l, kv, c.sysModule)
		if err != nil {
			return nil, kv, err
		}
		return append(found, attrs...), kv, nil
	}
	found, kv, err := run()
	if err != nil {
		limit("%v", err)
		return res
	}
	res.ran = true
	res.listed, res.kobjects, res.tree = kv.counts()
	for _, lm := range kv.limits {
		rec.Limit("Kernel memory view of the modules incomplete: %s", lm)
	}
	if len(found) > 0 {
		time.Sleep(300 * time.Millisecond)
		again, _, err := run()
		if err != nil {
			limit("second read: %v", err)
			return kernelResult{}
		}
		var confirmed []kfinding
		for _, f := range found {
			if stillKind(again, f) {
				confirmed = append(confirmed, f)
			}
		}
		found = confirmed
	}
	for _, f := range found {
		if f.hidden {
			res.hidden++
		} else {
			res.dangling++
		}
		rec.Suspicious(core.Finding{
			Description: f.desc,
			Details:     f.details,
			Why:         f.why,
			Benign:      "A module loading or unloading during the scan; unlikely, since it was seen in two reads 300 ms apart.",
		})
	}
	return res
}

// stillKind reports whether again holds a finding of the same kind for the
// same module.
func stillKind(again []kfinding, f kfinding) bool {
	for _, g := range again {
		if g.module == f.module && g.hidden == f.hidden {
			return true
		}
	}
	return false
}
