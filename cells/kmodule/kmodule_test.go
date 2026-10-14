package kmodule

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/waldh4ri/zygarde/internal/core"
)

// fixture builds a fake /proc/modules and /sys/module.
func fixture(t *testing.T, procModules []string, loadable, builtin []string, btf ...string) *Cell {
	t.Helper()
	dir := t.TempDir()
	proc := filepath.Join(dir, "modules")
	var content string
	for _, m := range procModules {
		content += m + " 16384 0 - Live 0x0000000000000000\n"
	}
	if err := os.WriteFile(proc, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	sys := filepath.Join(dir, "module")
	for _, m := range loadable {
		if err := os.MkdirAll(filepath.Join(sys, m), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sys, m, "initstate"), []byte("live\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, m := range builtin {
		if err := os.MkdirAll(filepath.Join(sys, m, "parameters"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	btfDir := filepath.Join(dir, "btf")
	if err := os.MkdirAll(btfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, m := range append(btf, "vmlinux") {
		if err := os.WriteFile(filepath.Join(btfDir, m), nil, 0o444); err != nil {
			t.Fatal(err)
		}
	}
	return &Cell{procModules: proc, sysModule: sys, sysBTF: btfDir}
}

func run(t *testing.T, c *Cell) []core.Finding {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := core.RunCell(context.Background(), &core.Env{Log: log}, c)
	if r.Error != "" {
		t.Fatal(r.Error)
	}
	return r.Findings
}

func TestConsistent(t *testing.T) {
	c := fixture(t, []string{"ext4", "nf_tables"}, []string{"ext4", "nf_tables"}, []string{"printk", "kernel"})
	if f := run(t, c); len(f) != 0 {
		t.Errorf("unexpected findings: %+v", f)
	}
}

func TestHiddenFromProcModules(t *testing.T) {
	// list_del'd module: still has its kobject, missing from the list.
	c := fixture(t, []string{"ext4"}, []string{"ext4", "diamorphine"}, []string{"printk"})
	f := run(t, c)
	if len(f) != 1 || f[0].Details["module"] != "diamorphine" {
		t.Fatalf("findings = %+v, want diamorphine hidden from /proc/modules", f)
	}
}

func TestHiddenFromSysfs(t *testing.T) {
	// kobject_del'd module: still in the list, no sysfs entry.
	c := fixture(t, []string{"ext4", "rootkit"}, []string{"ext4"}, nil)
	f := run(t, c)
	if len(f) != 1 || f[0].Details["module"] != "rootkit" {
		t.Fatalf("findings = %+v, want rootkit hidden from /sys/module", f)
	}
}

func TestCompare(t *testing.T) {
	notInProc, notInSys := Compare(
		map[string]bool{"a": true, "b": true},
		map[string]bool{"b": true, "c": true},
	)
	if !slices.Equal(notInProc, []string{"c"}) || !slices.Equal(notInSys, []string{"a"}) {
		t.Errorf("Compare = %v, %v", notInProc, notInSys)
	}
}

func TestHiddenButBTFRemains(t *testing.T) {
	// Unlinked from the module list and its kobject deleted: only the BTF
	// registration is left.
	c := fixture(t, []string{"ext4"}, []string{"ext4"}, nil, "ext4", "stealthmod")
	f := run(t, c)
	if len(f) != 1 || f[0].Details["module"] != "stealthmod" {
		t.Fatalf("findings = %+v, want stealthmod found through BTF", f)
	}
}

func TestBTFNotDoubleReported(t *testing.T) {
	// Already caught through /sys/module: BTF must not add a second finding.
	c := fixture(t, []string{"ext4"}, []string{"ext4", "diamorphine"}, nil, "ext4", "diamorphine")
	if f := run(t, c); len(f) != 1 {
		t.Fatalf("findings = %+v, want exactly 1", f)
	}
}
