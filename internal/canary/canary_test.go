// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package canary

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestParseCanaryPID(t *testing.T) {
	for in, want := range map[string]int{
		"tmp-deadbeef-4242-0123456789ab": 4242,
		"zygarde-canary-77-abc":          77,
		"tmp-short-4242-0123456789ab":    0,
		"tmp-deadbeef-x-0123456789ab":    0,
		"unrelated":                      0,
	} {
		if got := parseCanaryPID(in); got != want {
			t.Errorf("parseCanaryPID(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestRemoveStale(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("only root-owned files are removed")
	}
	dir := t.TempDir()
	dead := 4000000
	for unix.Kill(dead, 0) == nil {
		dead++
	}
	mk := func(name string, age time.Duration) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		at := time.Now().Add(-age)
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
		return p
	}
	old := mk(fmt.Sprintf("tmp-deadbeef-%d-0123456789ab", dead), 2*time.Minute)
	fresh := mk(fmt.Sprintf("tmp-deadbeef-%d-ba9876543210", dead), 5*time.Second)
	alive := mk(fmt.Sprintf("tmp-deadbeef-%d-aaaaaaaaaaaa", os.Getpid()), 2*time.Minute)

	RemoveStale(dir)

	if _, err := os.Stat(old); err == nil {
		t.Error("an old file of a dead process was kept")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("a fresh file was removed")
	}
	if _, err := os.Stat(alive); err != nil {
		t.Error("a file of a live process was removed")
	}
}
