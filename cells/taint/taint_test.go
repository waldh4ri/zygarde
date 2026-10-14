package taint

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/waldh4ri/zygarde/internal/core"
)

func fixture(t *testing.T, mask uint64, modules map[string]string) *Cell {
	t.Helper()
	dir := t.TempDir()
	tainted := filepath.Join(dir, "tainted")
	if err := os.WriteFile(tainted, []byte(strconv.FormatUint(mask, 10)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sys := filepath.Join(dir, "module")
	if err := os.MkdirAll(sys, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, taint := range modules {
		if err := os.MkdirAll(filepath.Join(sys, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if taint == "-" {
			continue // built-in: no taint attribute
		}
		if err := os.WriteFile(filepath.Join(sys, name, "taint"), []byte(taint+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &Cell{tainted: tainted, sysModule: sys}
}

func run(t *testing.T, c *Cell) core.Result {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := core.RunCell(context.Background(), &core.Env{Log: log}, c)
	if r.Error != "" {
		t.Fatal(r.Error)
	}
	return r
}

const (
	taintO = 1 << 12
	taintE = 1 << 13
	taintW = 1 << 9
)

func TestClean(t *testing.T) {
	r := run(t, fixture(t, 0, map[string]string{"ext4": "", "printk": "-"}))
	if r.Status != core.StatusOK {
		t.Errorf("status %v, findings %+v", r.Status, r.Findings)
	}
}

func TestExplainedByVisibleModule(t *testing.T) {
	r := run(t, fixture(t, taintO|taintE|taintW, map[string]string{"vboxdrv": "OE", "ext4": ""}))
	if r.Status != core.StatusOK {
		t.Errorf("status %v, findings %+v", r.Status, r.Findings)
	}
}

func TestUnexplainedTaint(t *testing.T) {
	// An out-of-tree, unsigned module tainted the kernel and is no longer visible.
	r := run(t, fixture(t, taintO|taintE, map[string]string{"ext4": ""}))
	if r.Status != core.StatusSuspicious || len(r.Findings) != 2 {
		t.Fatalf("status %v, findings %+v; want 2 findings (O and E)", r.Status, r.Findings)
	}
}

func TestPartiallyExplained(t *testing.T) {
	// A signed out-of-tree module is visible; the unsigned one isn't.
	r := run(t, fixture(t, taintO|taintE, map[string]string{"zfs": "O"}))
	if len(r.Findings) != 1 || r.Findings[0].Details["taint"] != "E" {
		t.Fatalf("findings %+v; want only E unexplained", r.Findings)
	}
}

func TestNonModuleTaintIgnored(t *testing.T) {
	r := run(t, fixture(t, taintW, nil))
	if r.Status != core.StatusOK {
		t.Errorf("a WARN taint must not be flagged: %+v", r.Findings)
	}
}
