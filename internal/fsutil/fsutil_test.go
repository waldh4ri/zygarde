package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileMetadataAndPreserve(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "implant")
	if err := os.WriteFile(src, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	meta := FileMetadata(src)
	if meta["sha256"] == "" || meta["size"] != "18" || meta["mtime"] == "" {
		t.Fatalf("unexpected metadata: %+v", meta)
	}

	entries, err := ReadDirNoAtime(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "implant" {
		t.Fatalf("ReadDirNoAtime = %v, %v", entries, err)
	}

	outDir := filepath.Join(dir, "preserved")
	saved, digest, err := PreserveBinary(src, outDir, "pid-42-implant")
	if err != nil {
		t.Fatal(err)
	}
	if digest != meta["sha256"] {
		t.Errorf("digest = %s, want %s", digest, meta["sha256"])
	}
	if _, err := os.Stat(saved); err != nil {
		t.Errorf("preserved file missing: %v", err)
	}
}

func TestWithCommVal(t *testing.T) {
	v, err := WithCommVal("ps", func() (int, error) { return 7, nil })
	if err != nil || v != 7 {
		t.Fatalf("got %d, %v", v, err)
	}
}
