package userhooks

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/waldh4ri/zygarde/internal/core"
)

func TestParsePreload(t *testing.T) {
	got := ParsePreload([]byte("# comment\n/lib/a.so /lib/b.so:/lib/c.so\n\t/lib/d.so # trailing\n\n"))
	want := []string{"/lib/a.so", "/lib/b.so", "/lib/c.so", "/lib/d.so"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("got %v, want %v", got, want)
	}
	if len(ParsePreload([]byte("# only a comment\n"))) != 0 {
		t.Error("comment-only file produced entries")
	}
}

func TestParseEnviron(t *testing.T) {
	env := ParseEnviron([]byte("PATH=/bin\x00LD_PRELOAD=/x.so\x00EMPTY=\x00junk\x00"))
	if env["LD_PRELOAD"] != "/x.so" || env["PATH"] != "/bin" || len(env) != 3 {
		t.Errorf("got %v", env)
	}
}

// TestRun checks a fixture system with every kind of injection point.
func TestRun(t *testing.T) {
	root := t.TempDir()
	proc := t.TempDir()
	write := func(base, p, content string, mode os.FileMode) {
		full := filepath.Join(base, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(root, "/usr/lib/libgood.so", "\x7fELF", 0o644)
	write(root, "/etc/ld.so.preload", "/usr/lib/libgood.so\n/dev/shm/libevil.so\n", 0o644)
	write(root, "/etc/ld.so.conf", "include ld.so.conf.d/*.conf\n/usr/local/lib\n", 0o644)
	write(root, "/etc/ld.so.conf.d/x86_64.conf", "/usr/lib/x86_64-linux-gnu\n", 0o644)
	write(root, "/etc/ld.so.conf.d/bad.conf", "/var/tmp/.lib\n", 0o644)

	// Process 100 preloads a library that no longer exists in its root.
	write(proc, "100/environ", "PATH=/bin\x00LD_PRELOAD=/opt/gone.so\x00", 0o644)
	if err := os.MkdirAll(filepath.Join(proc, "100/root"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(proc, "101/environ", "LD_LIBRARY_PATH=/dev/shm/x:/usr/lib\x00", 0o644)
	write(proc, "102/environ", "HOME=/root\x00", 0o644)

	c := &Cell{root: root, proc: proc}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rec := core.NewRecorder(log)
	if err := c.Run(context.Background(), &core.Env{Log: log}, rec); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range rec.Findings() {
		got = append(got, f.Description)
	}
	sort.Strings(got)
	all := strings.Join(got, "\n")
	for _, want := range []string{
		"/etc/ld.so.preload preloads 2 libraries",
		"Preloaded library /dev/shm/libevil.so (/etc/ld.so.preload): it lives in a memory-backed directory",
		"searches /var/tmp/.lib for libraries",
		"Preloaded library /opt/gone.so (LD_PRELOAD of process 100): it is missing from disk",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing finding %q in:\n%s", want, all)
		}
	}
	if len(got) != 4 {
		t.Errorf("got %d findings, want 4:\n%s", len(got), all)
	}
}

// A container's absolute symlinks must resolve inside its root, and a
// library counts as missing only if every process using it lacks it.
func TestCheckLibraryInRoot(t *testing.T) {
	proc := t.TempDir()
	ctr := filepath.Join(proc, "200", "root")
	if err := os.MkdirAll(filepath.Join(ctr, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(ctr, "real", "libx.so"), []byte("x"), 0o644)
	os.MkdirAll(filepath.Join(ctr, "usr"), 0o755)
	// /usr/lib -> /real, absolute: resolved against the host it would not exist.
	if err := os.Symlink("/real", filepath.Join(ctr, "usr", "lib")); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(proc, "201", "root")
	os.MkdirAll(other, 0o755)

	c := &Cell{root: t.TempDir(), proc: proc}
	rec := core.NewRecorder(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if n := c.checkLibrary(rec, "/usr/lib/libx.so", []string{ctr}, "test"); n != 0 {
		t.Fatalf("library present through an in-root symlink was flagged: %+v", rec.Findings())
	}
	if n := c.checkLibrary(rec, "/usr/lib/libx.so", []string{other, ctr}, "test"); n != 0 {
		t.Fatalf("library present for one of the processes was flagged: %+v", rec.Findings())
	}
	if n := c.checkLibrary(rec, "/usr/lib/libgone.so", []string{other, ctr}, "test"); n != 1 {
		t.Fatalf("library missing everywhere was not flagged")
	}
}

// ld.so.conf files including each other must be read once each.
func TestLdSoConfIncludeLoop(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc", "ld.so.conf.d"), 0o755)
	os.WriteFile(filepath.Join(root, "etc", "ld.so.conf"), []byte("include /etc/ld.so.conf.d/*.conf\n"), 0o644)
	for i := 0; i < 10; i++ {
		os.WriteFile(filepath.Join(root, "etc", "ld.so.conf.d", fmt.Sprintf("%d.conf", i)),
			[]byte(fmt.Sprintf("include /etc/ld.so.conf\ninclude /etc/ld.so.conf.d/*.conf\n/opt/lib%d\n", i)), 0o644)
	}
	c := &Cell{root: root}
	w := &confWalk{visited: map[string]bool{}}
	dirs := c.ldSoConfDirs("/etc/ld.so.conf", 0, w)
	if len(dirs) != 10 || w.files != 11 {
		t.Fatalf("got %d directories from %d files, want 10 from 11", len(dirs), w.files)
	}
}

func TestParsePreloadLongLine(t *testing.T) {
	data := []byte("# " + strings.Repeat("x", 200*1024) + "\n/lib/evil.so\n")
	if got := ParsePreload(data); len(got) != 1 || got[0] != "/lib/evil.so" {
		t.Fatalf("got %v", got)
	}
}
