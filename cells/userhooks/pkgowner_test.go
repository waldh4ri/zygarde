package userhooks

import (
	"os"
	"path/filepath"
	"testing"
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
	got := dpkgOwners(info, wanted)
	if got["/usr/lib/x86_64-linux-gnu/security/pam_unix.so"] == "" || got["/usr/lib/x86_64-linux-gnu/libfoo.so.1"] == "" {
		t.Errorf("owned libraries not found: %v", got)
	}
	if got["/usr/lib/x86_64-linux-gnu/security/pam_evil.so"] != "" {
		t.Errorf("unowned library reported as owned: %v", got)
	}
}

func TestAddPAMModules(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "usr/lib/x86_64-linux-gnu/security")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pam_evil.so"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("pam_evil.so", filepath.Join(dir, "pam_link.so")); err != nil {
		t.Fatal(err)
	}
	c := &Cell{root: root}
	m := map[string][]string{}
	c.addPAMModules(m)
	if _, ok := m["/usr/lib/x86_64-linux-gnu/security/pam_evil.so"]; !ok || len(m) != 1 {
		t.Errorf("addPAMModules = %v", m)
	}
}
