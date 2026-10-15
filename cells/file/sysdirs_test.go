package file

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/waldh4ri/zygarde/internal/core"
)

func TestDotEntries(t *testing.T) {
	dir := t.TempDir()
	mk := func(p string, mode os.FileMode, content string) {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	mk(".local/sudo", 0o755, "#!/bin/sh\n")       // trojan in a dot-directory: suspicious
	mk(".cache/notes", 0o644, "text")             // dot-directory without executables: observation
	mk(".lib.so", 0o644, "\x7fELF....")           // dot-file that is an ELF object: suspicious
	mk(".libcrypto.so.3.hmac", 0o644, "abc")      // FIPS checksum: allowed
	mk(".build-id/aa/bbbb", 0o755, "#!/bin/sh\n") // debuginfo links: allowed
	mk("ls", 0o755, "#!/bin/sh\n")                // not a dot-entry
	entries, _ := os.ReadDir(dir)
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name()] = true
	}

	rec := core.NewRecorder(slog.New(slog.NewTextHandler(io.Discard, nil)))
	n := dotEntries(rec, dir, names, map[string]bool{})
	if n != 2 {
		t.Fatalf("got %d suspicious entries, want 2: %+v", n, rec.Findings())
	}
	var descs []string
	for _, f := range rec.Findings() {
		descs = append(descs, f.Description)
	}
	all := strings.Join(descs, "\n")
	if !strings.Contains(all, ".local") || !strings.Contains(all, ".lib.so") {
		t.Errorf("unexpected findings:\n%s", all)
	}

	// The same directory under another name is not checked twice.
	if n := dotEntries(rec, dir, names, map[string]bool{mustReal(t, dir): true}); n != 0 {
		t.Errorf("rechecked an already seen directory: %d", n)
	}
}

func mustReal(t *testing.T, p string) string {
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
