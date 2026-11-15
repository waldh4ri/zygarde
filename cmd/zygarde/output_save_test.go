package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/waldh4ri/zygarde/internal/report"
)

// -o never replaces anything: regular files, symlinks (dangling too), pipes
// and devices are refused before the scan.
func TestCheckOutputRefusesExisting(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "existing.json")
	if err := os.WriteFile(file, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{file, link, fifo, "/dev/null", dir} {
		if err := checkOutputWritable(p); !errors.Is(err, errOutputExists) {
			t.Errorf("checkOutputWritable(%s) = %v, want errOutputExists", p, err)
		}
	}
	if err := checkOutputWritable(filepath.Join(dir, "new.json")); err != nil {
		t.Errorf("new path refused: %v", err)
	}
	if err := checkOutputWritable(filepath.Join(dir, "missing", "new.json")); err == nil {
		t.Error("path in a missing directory accepted")
	}
}

func TestSaveReportNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	rep := report.New("test", nil)
	path := filepath.Join(dir, "r.json")
	if err := saveReport(rep, path); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("report not saved with mode 0600: %v %v", st, err)
	}
	// Something appearing at the path during the scan is kept, not replaced.
	taken := filepath.Join(dir, "taken.json")
	if err := os.WriteFile(taken, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := saveReport(rep, taken); !errors.Is(err, errOutputExists) {
		t.Errorf("saveReport over an existing file = %v, want errOutputExists", err)
	}
	if b, _ := os.ReadFile(taken); string(b) != "keep" {
		t.Errorf("existing file changed: %q", b)
	}
	if err := writeNew(taken, []byte("x")); !errors.Is(err, errOutputExists) {
		t.Errorf("writeNew over an existing file = %v, want errOutputExists", err)
	}
	// No temporary file is left behind.
	if m, _ := filepath.Glob(filepath.Join(dir, ".zygarde-report-*")); len(m) != 0 {
		t.Errorf("temporary files left: %v", m)
	}
}
