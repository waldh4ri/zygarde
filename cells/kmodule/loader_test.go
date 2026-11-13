package kmodule

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/waldh4ri/zygarde/internal/kattr"
)

func TestOrphanLoaderAreas(t *testing.T) {
	areas := []kattr.Area{
		{Start: 0xffffffffc0100000, End: 0xffffffffc0110000, Caller: "load_module"}, // ext4: base inside
		{Start: 0xffffffffc0200000, End: 0xffffffffc0210000, Caller: "load_module"}, // jbd2: only a section inside
		{Start: 0xffffffffc0300000, End: 0xffffffffc0305000, Caller: "load_module"}, // owned by nobody
		{Start: 0xffffffffc0400000, End: 0xffffffffc0401000, Caller: "bpf_prog_alloc"},
		{Start: 0xffffffffc0500000, End: 0xffffffffc0501000, Caller: "irq_init_percpu_irqstack"},
	}
	mods := []kattr.ModuleInfo{
		{Name: "ext4", Base: 0xffffffffc0100000},
		{Name: "jbd2", Base: 0xffffffffc0000000}, // base is elsewhere (separate data mapping)
	}
	sections := map[string]map[string]uint64{"jbd2": {".data": 0xffffffffc0208000}}

	got, considered := orphanLoaderAreas(areas, mods, sections)
	if considered != 3 {
		t.Errorf("considered %d loader areas, want 3", considered)
	}
	if len(got) != 1 || got[0].Start != 0xffffffffc0300000 || got[0].End != 0xffffffffc0305000 {
		t.Fatalf("orphans = %+v", got)
	}

	// A kernel with no per-module allocations has nothing to compare.
	if _, n := orphanLoaderAreas([]kattr.Area{{Start: 1 << 63, End: 1<<63 + 4096, Caller: "execmem_alloc"}}, mods, nil); n != 0 {
		t.Errorf("shared execmem areas were considered: %d", n)
	}
	// The boundary: an area ending exactly at an anchor does not contain it.
	edge, _ := orphanLoaderAreas([]kattr.Area{{Start: 0x1000, End: 0x2000, Caller: "load_module"}}, []kattr.ModuleInfo{{Name: "x", Base: 0x2000}}, nil)
	if len(edge) != 1 {
		t.Errorf("half-open range not respected: %+v", edge)
	}
}

func TestCountLoaderAreas(t *testing.T) {
	// /proc/vmallocinfo on Linux 5.10 with hashed addresses.
	in := `0x00000000ebbbae88-0x00000000c42472b8  147456 load_module+0xd97/0x2630 pages=35 vmalloc N0=35
0x00000000c42472b8-0x00000000d6ceb1b6   20480 load_module+0xd97/0x2630 pages=4 vmalloc N0=4
0x00000000e96e1a05-0x00000000213b8dde   20480 irq_init_percpu_irqstack+0xcf/0x100 vmap
0x00000000213b8dde-0x00000000dbb2e80c    8192 acpi_os_map_iomem+0x1c7/0x1e0 phys=0x00000000f7ff8000 ioremap
0x00000000b540d104-0x000000003ec05ab5
`
	p := filepath.Join(t.TempDir(), "vmallocinfo")
	if err := os.WriteFile(p, []byte(in), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := countLoaderAreas(p)
	if err != nil || n != 2 {
		t.Errorf("countLoaderAreas = %d, %v; want 2", n, err)
	}
	v := loaderView{areas: 3, listed: 2, byCount: true}
	if v.excess() != 1 || (loaderView{areas: 2, listed: 2, byCount: true}).excess() != 0 || (loaderView{areas: 1, listed: 2, byCount: true}).excess() != 0 {
		t.Error("excess by count")
	}
	if (loaderView{orphans: []loaderArea{{1, 2}}}).excess() != 1 {
		t.Error("excess by address")
	}
}

func TestOnePerModule(t *testing.T) {
	for rel, want := range map[string]bool{
		"4.18.0-553.el8_10.x86_64": true, "5.4.0-216-generic": true, "5.10.0-46-amd64": true, "5.15.0-203-generic": true,
		"6.1.0-13-amd64": true, "6.3.9": true, "6.4.0": false, "6.8.0-147-generic": false, "6.12.0-211.74.2.el10_2.x86_64": false,
		"7.0.0-43-generic": false, "garbage": false, "": false,
	} {
		if got := onePerModule(rel); got != want {
			t.Errorf("onePerModule(%q) = %v, want %v", rel, got, want)
		}
	}
}
