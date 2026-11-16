// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package kmodule

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/waldh4ri/zygarde/internal/kmem"
)

const kbase uint64 = 0xffffffffc0000000

// testLayout is a made-up struct layout; the walks only use the offsets.
var testLayout = modLayout{
	list: 8, name: 24, nameLen: 56, state: 0, sectAttrs: 128, notesAttrs: 136, hasSect: true, hasNotes: true,
	kobjEntry: 8, kobjToMod: 64, ksetList: 0,
	hasTree: true, treeRoots: 8, mtnMod: 0, mtnNode: 8, rbNode: 24, rbRight: 8, rbLeft: 16,
	grpName: 0, grpAttrs: 24, grpBinAttrs: 32, hasBinAttrs: true, attrName: 0,
}

// fakeKernel lays out modules, the module list, module_kset and mod_tree in
// fake memory.
type fakeKernel struct {
	m    *kmem.Fake
	syms modSyms
	mods map[string]uint64 // name -> struct module address
	n    int
}

func newFakeKernel() *fakeKernel {
	return &fakeKernel{m: kmem.NewFake(), mods: map[string]uint64{},
		syms: modSyms{modules: kbase, kset: kbase + 0x100, tree: kbase + 0x200}}
}

func (k *fakeKernel) addr(name string) uint64 {
	if a, ok := k.mods[name]; ok {
		return a
	}
	k.n++
	a := kbase + 0x10000*uint64(k.n)
	k.mods[name] = a
	k.m.Put32(a+testLayout.state, moduleStateLive)
	k.m.PutString(a+testLayout.name, name)
	k.m.Put64(a+testLayout.sectAttrs, 0)
	k.m.Put64(a+testLayout.notesAttrs, 0)
	return a
}

// circular links nodes (list_head addresses) after head.
func (k *fakeKernel) circular(head uint64, nodes []uint64) {
	all := append([]uint64{head}, nodes...)
	for i, n := range all {
		k.m.Put64(n, all[(i+1)%len(all)])
		k.m.Put64(n+8, all[(i+len(all)-1)%len(all)])
	}
}

// build writes the three views: list, kset and tree hold the named modules.
func (k *fakeKernel) build(list, kset, tree []string) {
	var nodes []uint64
	for _, n := range list {
		nodes = append(nodes, k.addr(n)+testLayout.list)
	}
	k.circular(k.syms.modules, nodes)

	ksetStruct := uint64(kbase + 0x1000)
	k.m.Put64(k.syms.kset, ksetStruct)
	nodes = nil
	for _, n := range kset {
		kobj := k.addr(n) + 0x200
		k.m.Put64(kobj+testLayout.kobjToMod, k.addr(n))
		nodes = append(nodes, kobj+testLayout.kobjEntry)
	}
	builtin := uint64(kbase + 0x2000) // a built-in module's kobject: no struct module
	k.m.Put64(builtin+testLayout.kobjToMod, 0)
	nodes = append(nodes, builtin+testLayout.kobjEntry)
	k.circular(ksetStruct+testLayout.ksetList, nodes)

	// Both latch copies: a right-leaning chain of mod_tree_nodes.
	for c := uint64(0); c < 2; c++ {
		var prev uint64
		for i, n := range tree {
			mtn := k.addr(n) + 0x400
			k.m.Put64(mtn+testLayout.mtnMod, k.addr(n))
			rb := mtn + testLayout.mtnNode + c*testLayout.rbNode
			k.m.Put64(rb+testLayout.rbRight, 0)
			k.m.Put64(rb+testLayout.rbLeft, 0)
			if i == 0 {
				k.m.Put64(k.syms.tree+testLayout.treeRoots+8*c, rb)
			} else {
				k.m.Put64(prev+testLayout.rbRight, rb)
			}
			prev = rb
		}
		if len(tree) == 0 {
			k.m.Put64(k.syms.tree+testLayout.treeRoots+8*c, 0)
		}
	}
}

func set(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

func TestKernelViewClean(t *testing.T) {
	k := newFakeKernel()
	all := []string{"ext4", "xfs", "e1000"}
	k.build(all, all, all)
	visible := views{proc: set(all...), sys: set(all...)}
	kv, err := readKernelView(k.m, testLayout, k.syms, visible)
	if err != nil {
		t.Fatal(err)
	}
	if !kv.ksetOK || !kv.treeOK || len(kv.limits) > 0 {
		t.Fatalf("ksetOK=%v treeOK=%v limits=%q", kv.ksetOK, kv.treeOK, kv.limits)
	}
	if miss := kv.listComplete(visible); len(miss) > 0 {
		t.Errorf("listComplete missed %q", miss)
	}
	if f := compareViews(kv, visible, nil); len(f) > 0 {
		t.Errorf("findings on a clean kernel: %+v", f)
	}
}

func TestKernelViewHiddenEverywhereButTree(t *testing.T) {
	k := newFakeKernel()
	k.build([]string{"ext4", "xfs"}, []string{"ext4", "xfs"}, []string{"ext4", "xfs", "rootkit"})
	visible := views{proc: set("ext4", "xfs"), sys: set("ext4", "xfs")}
	kv, err := readKernelView(k.m, testLayout, k.syms, visible)
	if err != nil {
		t.Fatal(err)
	}
	f := compareViews(kv, visible, nil)
	if len(f) != 1 || f[0].module != "rootkit" || !f[0].hidden ||
		!strings.Contains(f[0].desc, "mod_tree") || strings.Contains(f[0].desc, "kobject") ||
		!strings.Contains(f[0].why, "deleted its /sys/module entry") {
		t.Fatalf("findings = %+v, want rootkit in mod_tree only", f)
	}
}

func TestKernelViewListDel(t *testing.T) {
	k := newFakeKernel()
	all := []string{"ext4", "diamorphine"}
	k.build([]string{"ext4"}, all, all)
	visible := views{proc: set("ext4"), sys: set(all...)}
	kv, err := readKernelView(k.m, testLayout, k.syms, visible)
	if err != nil {
		t.Fatal(err)
	}
	if f := compareViews(kv, visible, set("diamorphine")); len(f) != 0 {
		t.Errorf("an already reported module was reported again: %+v", f)
	}
	f := compareViews(kv, visible, nil)
	if len(f) != 1 || !strings.Contains(f[0].desc, "mod_tree") || !strings.Contains(f[0].desc, "kobject") {
		t.Errorf("findings = %+v, want diamorphine in mod_tree and the kobject set", f)
	}
}

func TestKernelViewFilteredProcModules(t *testing.T) {
	k := newFakeKernel()
	all := []string{"ext4", "hidden"}
	k.build(all, []string{"ext4"}, all)
	visible := views{proc: set("ext4"), sys: set("ext4")}
	kv, err := readKernelView(k.m, testLayout, k.syms, visible)
	if err != nil {
		t.Fatal(err)
	}
	if miss := kv.listComplete(visible); len(miss) > 0 {
		t.Fatalf("listComplete missed %q", miss)
	}
	f := compareViews(kv, visible, nil)
	if len(f) != 1 || f[0].module != "hidden" || !strings.Contains(f[0].desc, "/proc/modules does not show") {
		t.Errorf("findings = %+v, want hidden filtered from /proc/modules", f)
	}
}

func TestKernelViewSkipsTransientModules(t *testing.T) {
	k := newFakeKernel()
	k.build([]string{"ext4"}, []string{"ext4"}, []string{"ext4", "loading"})
	k.m.Put32(k.addr("loading")+testLayout.state, 1) // MODULE_STATE_COMING
	visible := views{proc: set("ext4"), sys: set("ext4")}
	kv, err := readKernelView(k.m, testLayout, k.syms, visible)
	if err != nil {
		t.Fatal(err)
	}
	if f := compareViews(kv, visible, nil); len(f) != 0 {
		t.Errorf("a loading module was reported: %+v", f)
	}
}

func TestKernelViewDistrustsIncompleteWalks(t *testing.T) {
	k := newFakeKernel()
	all := []string{"ext4", "xfs"}
	k.build(all, []string{"ext4"}, []string{"ext4"}) // kset and tree miss xfs
	visible := views{proc: set(all...), sys: set(all...)}
	kv, err := readKernelView(k.m, testLayout, k.syms, visible)
	if err != nil {
		t.Fatal(err)
	}
	if kv.ksetOK || kv.treeOK || len(kv.limits) != 2 {
		t.Fatalf("ksetOK=%v treeOK=%v limits=%q, want both distrusted", kv.ksetOK, kv.treeOK, kv.limits)
	}
	// The list walk itself missing a visible module is caught by listComplete.
	visible.proc["zfs"] = true
	if miss := kv.listComplete(visible); len(miss) != 1 || miss[0] != "zfs" {
		t.Errorf("listComplete = %q, want [zfs]", miss)
	}
}

func TestKernelViewDropsGarbageTreeNodes(t *testing.T) {
	k := newFakeKernel()
	k.build([]string{"ext4"}, []string{"ext4"}, []string{"ext4"})
	// A tree node whose mod pointer leads to unreadable memory.
	mtn := uint64(kbase + 0x900000)
	k.m.Put64(mtn+testLayout.mtnMod, kbase+0x7000000)
	for c := uint64(0); c < 2; c++ {
		rb := mtn + testLayout.mtnNode + c*testLayout.rbNode
		k.m.Put64(rb+testLayout.rbRight, 0)
		k.m.Put64(rb+testLayout.rbLeft, 0)
		root := k.addr("ext4") + 0x400 + testLayout.mtnNode + c*testLayout.rbNode
		k.m.Put64(root+testLayout.rbLeft, rb)
	}
	visible := views{proc: set("ext4"), sys: set("ext4")}
	kv, err := readKernelView(k.m, testLayout, k.syms, visible)
	if err != nil {
		t.Fatal(err)
	}
	if len(kv.mods) != 1 {
		t.Errorf("mods = %d, want only ext4", len(kv.mods))
	}
}

// sysfs creates <root>/<module>/<dir>/<files>.
func sysfs(t *testing.T, root, module, dir string, files ...string) {
	t.Helper()
	d := filepath.Join(root, module, dir)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(d, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// sectAttrs writes a module_sect_attrs naming sections at addr.
func (k *fakeKernel) sectAttrs(addr uint64, group string, sections ...string) {
	l := testLayout
	k.m.Put64(addr+l.grpName, addr+0x800)
	k.m.PutString(addr+0x800, group)
	k.m.Put64(addr+l.grpAttrs, 0)
	arr := addr + 0x100
	k.m.Put64(addr+l.grpBinAttrs, arr)
	for i, s := range sections {
		attr := addr + 0x1000 + 0x40*uint64(i)
		k.m.Put64(arr+8*uint64(i), attr)
		k.m.Put64(attr+l.attrName, attr+0x20)
		k.m.PutString(attr+0x20, s)
	}
	k.m.Put64(arr+8*uint64(len(sections)), 0)
}

func TestCheckAttrs(t *testing.T) {
	k := newFakeKernel()
	all := []string{"good", "freed", "reused", "nonotes", "nosysfs"}
	k.build(all, all, all)
	root := t.TempDir()
	for _, m := range all[:4] {
		sysfs(t, root, m, "sections", ".text", ".data")
	}
	sysfs(t, root, "nonotes", "notes", ".note.gnu.build-id")

	k.m.Put64(k.addr("good")+testLayout.sectAttrs, kbase+0x100000)
	k.sectAttrs(kbase+0x100000, "sections", ".text", ".data")
	k.m.Put64(k.addr("nonotes")+testLayout.sectAttrs, kbase+0x200000)
	k.sectAttrs(kbase+0x200000, "sections", ".text", ".data")
	// freed: sect_attrs set to NULL after kfree (Diamorphine).
	// reused: sect_attrs still set, but the memory now holds something else.
	k.m.Put64(k.addr("reused")+testLayout.sectAttrs, kbase+0x300000)
	k.sectAttrs(kbase+0x300000, "zzzzzzzz", ".text", ".data")

	visible := views{proc: set(all...), sys: set(all...)}
	kv, err := readKernelView(k.m, testLayout, k.syms, visible)
	if err != nil {
		t.Fatal(err)
	}
	f, err := checkAttrs(k.m, testLayout, kv, root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, x := range f {
		got[x.module] += x.desc + "\n"
	}
	if len(f) != 3 || !strings.Contains(got["freed"], "sect_attrs is NULL") ||
		!strings.Contains(got["reused"], "no longer holds") || !strings.Contains(got["nonotes"], "notes_attrs is NULL") {
		t.Fatalf("findings = %q", got)
	}
}

func TestCheckSectionsNameMismatch(t *testing.T) {
	k := newFakeKernel()
	k.sectAttrs(kbase+0x100000, "sections", ".text", ".bss")
	got, err := checkSections(k.m, testLayout, kbase+0x100000, []string{".text", ".data"})
	if err != nil || got == "" {
		t.Errorf("checkSections = %q, %v; want a mismatch", got, err)
	}
	got, err = checkSections(k.m, testLayout, kbase+0x100000, []string{".bss", ".text"})
	if err != nil || got != "" {
		t.Errorf("checkSections = %q, %v; want a match", got, err)
	}
}
