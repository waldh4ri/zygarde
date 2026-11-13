package kmodule

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCountLoaderAreas(t *testing.T) {
	// /proc/vmallocinfo on Linux 5.10 with hashed addresses.
	in := `0x00000000ebbbae88-0x00000000c42472b8  147456 load_module+0xd97/0x2630 pages=35 vmalloc N0=35
0x00000000c42472b8-0x00000000d6ceb1b6   20480 load_module+0xd97/0x2630 pages=4 vmalloc N0=4
0x00000000e96e1a05-0x00000000213b8dde   20480 irq_init_percpu_irqstack+0xcf/0x100 vmap
0x00000000213b8dde-0x00000000dbb2e80c    8192 acpi_os_map_iomem+0x1c7/0x1e0 phys=0x00000000f7ff8000 ioremap
0x00000000b540d104-0x000000003ec05ab5
0x00000000aaaaaaaa-0x00000000bbbbbbbb   24576 move_module+0x23/0x170 pages=5 vmalloc N0=5
0x00000000cccccccc-0x00000000dddddddd   28672 layout_and_allocate+0x5e7/0x8c0 pages=6 vmalloc N0=6
`
	p := filepath.Join(t.TempDir(), "vmallocinfo")
	if err := os.WriteFile(p, []byte(in), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := countLoaderAreas(p)
	if err != nil || n != 4 {
		t.Errorf("countLoaderAreas = %d, %v; want 4", n, err)
	}
}

func TestCountModules(t *testing.T) {
	in := `ext4 950272 1 - Live 0xffffffffc0588000
mbcache 16384 1 ext4, Live 0xffffffffc050f000
jbd2 151552 1 ext4, Live 0xffffffffc0555000

`
	p := filepath.Join(t.TempDir(), "modules")
	if err := os.WriteFile(p, []byte(in), 0o644); err != nil {
		t.Fatal(err)
	}
	if n, err := countModules(p); err != nil || n != 3 {
		t.Errorf("countModules = %d, %v; want 3", n, err)
	}
	if _, err := countModules(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing file")
	}
}

func TestLoaderViewExcess(t *testing.T) {
	for _, tc := range []struct {
		v    loaderView
		want int
	}{{loaderView{areas: 3, listed: 2}, 1}, {loaderView{areas: 2, listed: 2}, 0}, {loaderView{areas: 1, listed: 2}, 0}} {
		if got := tc.v.excess(); got != tc.want {
			t.Errorf("%+v excess = %d, want %d", tc.v, got, tc.want)
		}
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
