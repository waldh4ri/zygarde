// Copyright (c) 2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package userhooks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/waldh4ri/zygarde/internal/pkgdb"
)

func TestDpkgOwners(t *testing.T) {
	info := t.TempDir()
	list := "/.\n/lib/x86_64-linux-gnu/security/pam_unix.so\n/usr/lib/x86_64-linux-gnu/libfoo.so.1\n"
	if err := os.WriteFile(filepath.Join(info, "libpam-modules:amd64.list"), []byte(list), 0o644); err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{
		"/usr/lib/x86_64-linux-gnu/security/pam_unix.so": true, // listed under /lib (usr-merge)
		"/usr/lib/x86_64-linux-gnu/libfoo.so.1":          true,
		"/usr/lib/x86_64-linux-gnu/security/pam_evil.so": true,
	}
	got := pkgdb.DpkgOwners(info, wanted)
	if got["/usr/lib/x86_64-linux-gnu/security/pam_unix.so"] == "" || got["/usr/lib/x86_64-linux-gnu/libfoo.so.1"] == "" {
		t.Errorf("owned libraries not found: %v", got)
	}
	if got["/usr/lib/x86_64-linux-gnu/security/pam_evil.so"] != "" {
		t.Errorf("unowned library reported as owned: %v", got)
	}
}

func TestAddModuleFiles(t *testing.T) {
	root := t.TempDir()
	lib := filepath.Join(root, "usr/lib/x86_64-linux-gnu")
	dir := filepath.Join(lib, "security")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{filepath.Join(dir, "pam_evil.so"), filepath.Join(lib, "libnss_evil.so.2"), filepath.Join(lib, "libother.so.1")} {
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("pam_evil.so", filepath.Join(dir, "pam_link.so")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("libnss_evil.so.2", filepath.Join(lib, "libnss_evil.so")); err != nil {
		t.Fatal(err)
	}
	c := &Cell{root: root}
	m := map[string][]string{}
	c.addModuleFiles(m)
	_, pam := m["/usr/lib/x86_64-linux-gnu/security/pam_evil.so"]
	_, nss := m["/usr/lib/x86_64-linux-gnu/libnss_evil.so.2"]
	if !pam || !nss || len(m) != 2 {
		t.Errorf("addModuleFiles = %v", m)
	}
}
