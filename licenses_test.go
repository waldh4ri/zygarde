// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package zygarde

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbeddedNotices(t *testing.T) {
	notices := map[string]string{
		"LICENSE":              License,
		"THIRD_PARTY_LICENSES": ThirdParty,
	}
	for name, text := range notices {
		if strings.TrimSpace(text) == "" {
			t.Errorf("%s is empty", name)
		}
	}
	for _, want := range []string{
		"Copyright (c) 2025-2026 waldh4ri", "BSD-2-Clause", "GPL-2.0-only",
	} {
		if !strings.Contains(License, want) {
			t.Errorf("LICENSE lacks %q", want)
		}
	}
	for _, want := range []string{
		"cilium/ebpf", "golang.org/x/sys", "Go standard library", "libbpf",
	} {
		if !strings.Contains(ThirdParty, want) {
			t.Errorf("THIRD_PARTY_LICENSES lacks %q", want)
		}
	}
}

// Every hand-written Go and eBPF C source states its license. Generated
// bpf2go files and vendored headers are covered by REUSE.toml instead.
func TestSourcesHaveSPDXHeader(t *testing.T) {
	skipDirs := map[string]bool{".git": true, ".claude": true, "dist": true}
	walk := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		source := strings.HasSuffix(path, ".go") || strings.HasSuffix(path, ".bpf.c")
		if !source || strings.HasSuffix(path, "_bpfel.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		head := string(b[:min(len(b), 400)])
		if !strings.Contains(head, "SPDX-License-Identifier: ") {
			t.Errorf("%s has no SPDX-License-Identifier in its header", path)
		}
		return nil
	}
	if err := filepath.WalkDir(".", walk); err != nil {
		t.Fatal(err)
	}
}
