package userhooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSearchDirRisk(t *testing.T) {
	root := t.TempDir()
	mk := func(p string, mode os.FileMode) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(full, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(full, mode); err != nil {
			t.Fatal(err)
		}
	}
	mk("/usr/bin", 0o755)
	mk("/usr/lib/ok", 0o755)
	mk("/opt/ww", 0o777)
	mk("/srv/open", 0o777)
	c := &Cell{root: root}

	for _, tc := range []struct {
		entry, want string
		asRoot      bool // the expectation holds only when the fixture is owned by root
	}{
		{"", "empty entry", false},
		{"lib", "relative directory", false},
		{"$ORIGIN/../../tmp/x", "temporary directory", false},
		{"/dev/shm/l", "memory-backed", false},
		{"/usr/lib/.x", "hidden directory", false},
		{"/opt/ww", "world-writable", false},
		{"/srv/open/missing", "does not exist and /srv/open", true},
		{"/usr/lib/ok", "", true},
		{"$ORIGIN/../lib/ok", "", true},
		{"/usr/lib/absent", "", true},
		{"/usr/$LIB", "", false},
	} {
		if tc.asRoot && os.Getuid() != 0 {
			continue
		}
		got := c.searchDirRisk("/usr/bin", tc.entry)
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("searchDirRisk(%q) = %q, want %q", tc.entry, got, tc.want)
		}
	}
}
