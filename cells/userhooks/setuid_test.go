package userhooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/waldh4ri/zygarde/internal/fsutil"
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
		got := c.searchDirRisk("/usr/bin", tc.entry, false)
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("searchDirRisk(%q) = %q, want %q", tc.entry, got, tc.want)
		}
	}
}

// A program that a user can replace gains nothing from a search directory the
// same user controls; locations that are unsafe for anyone still count.
func TestSearchDirRiskControlledProgram(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "srv/open"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.Chmod(filepath.Join(root, "srv/open"), 0o777)
	c := &Cell{root: root}
	if got := c.searchDirRisk("/usr/bin", "/srv/open/missing", true); got != "" {
		t.Errorf("controlled program: got %q, want nothing", got)
	}
	for _, e := range []string{"", "lib", "/tmp/x"} {
		if c.searchDirRisk("/usr/bin", e, true) == "" {
			t.Errorf("entry %q not reported for a controlled program", e)
		}
	}
}

// /bin -> usr/bin: the program depends on /usr, which only the resolved path shows.
func TestControlledProgramThroughSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "usr/bin/prog"), []byte("x"), 0o755)
	if err := os.Symlink("usr/bin", filepath.Join(root, "bin")); err != nil {
		t.Fatal(err)
	}
	os.Chmod(filepath.Join(root, "usr"), 0o777)
	if got := fsutil.ControlledBy(root, "/bin/prog"); !strings.Contains(got, "/usr is writable by everyone") {
		t.Errorf("ControlledBy(/bin/prog) = %q, want /usr reported", got)
	}
}
