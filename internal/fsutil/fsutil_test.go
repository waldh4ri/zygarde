package fsutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOpenRegular(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	data, err := ReadFile(p, 100)
	if err != nil || string(data) != "hello" {
		t.Fatalf("ReadFile = %q, %v", data, err)
	}
}

func TestOpenRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte("x"), 0o644)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("Open(symlink) error = %v, want ErrNotRegular", err)
	}
	// A symlink to a device must never be opened.
	dev := filepath.Join(dir, "dev")
	os.Symlink("/dev/null", dev)
	if _, err := Open(dev); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("Open(symlink to device) error = %v, want ErrNotRegular", err)
	}
}

func TestOpenRefusesDevice(t *testing.T) {
	if _, err := Open("/dev/null"); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("Open(/dev/null) error = %v, want ErrNotRegular", err)
	}
}

func TestOpenFIFODoesNotBlock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(p, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ReadFile(p, 100)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Fatalf("ReadFile(fifo) error = %v, want ErrNotRegular", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("opening a FIFO blocked")
	}
	// And through OpenSystem (a FIFO is not a symlink to follow).
	if _, err := OpenSystem(p); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("OpenSystem(fifo) error = %v, want ErrNotRegular", err)
	}
}

func TestReadFileTooLarge(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big")
	os.WriteFile(p, []byte(strings.Repeat("a", 101)), 0o644)
	data, err := ReadFile(p, 100)
	if !errors.Is(err, ErrTooLarge) || len(data) != 100 {
		t.Fatalf("ReadFile = %d bytes, %v; want 100 bytes and ErrTooLarge", len(data), err)
	}
}

func TestOpenSystemFollowsOnlyTrustedLinks(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: trusted links are owned by root")
	}
	dir := t.TempDir()
	os.Chmod(dir, 0o755)
	target := filepath.Join(dir, "real.conf")
	os.WriteFile(target, []byte("ok"), 0o644)
	link := filepath.Join(dir, "link.conf")
	os.Symlink("real.conf", link)
	if data, err := ReadSystemFile(link, 100); err != nil || string(data) != "ok" {
		t.Fatalf("ReadSystemFile(trusted link) = %q, %v", data, err)
	}

	// The same link in a directory others can write to is not followed.
	open := filepath.Join(t.TempDir(), "open")
	os.Mkdir(open, 0o777)
	os.Chmod(open, 0o777)
	link2 := filepath.Join(open, "link.conf")
	os.Symlink(target, link2)
	if _, err := ReadSystemFile(link2, 100); !errors.Is(err, ErrUntrustedLink) {
		t.Fatalf("ReadSystemFile(link in world-writable dir) error = %v, want ErrUntrustedLink", err)
	}

	// A link owned by another user is not followed either.
	link3 := filepath.Join(dir, "user.conf")
	os.Symlink(target, link3)
	if err := os.Lchown(link3, 1000, 1000); err != nil {
		t.Skipf("lchown: %v", err)
	}
	if _, err := ReadSystemFile(link3, 100); !errors.Is(err, ErrUntrustedLink) {
		t.Fatalf("ReadSystemFile(user-owned link) error = %v, want ErrUntrustedLink", err)
	}

	// Trusted links to a device are still refused.
	dev := filepath.Join(dir, "dev.conf")
	os.Symlink("/dev/null", dev)
	if _, err := ReadSystemFile(dev, 100); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("ReadSystemFile(link to device) error = %v, want ErrNotRegular", err)
	}

	// Loops end.
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	os.Symlink("b", a)
	os.Symlink("a", b)
	if _, err := ReadSystemFile(a, 100); err == nil {
		t.Fatal("ReadSystemFile(symlink loop) succeeded")
	}
}

func TestScannerLongLine(t *testing.T) {
	long := strings.Repeat("x", 200*1024) // over bufio's default 64 KiB
	sc := NewScanner(strings.NewReader("first\n" + long + "\ninsmod /x.ko\n"))
	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil || len(lines) != 3 || lines[2] != "insmod /x.ko" {
		t.Fatalf("got %d lines, err %v", len(lines), err)
	}

	sc = NewScanner(strings.NewReader(strings.Repeat("y", MaxLine+2) + "\nafter\n"))
	for sc.Scan() {
	}
	if sc.Err() == nil {
		t.Fatal("a line over MaxLine must be reported through Err()")
	}
}

func TestInListing(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3000; i++ {
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%d", i)), nil, 0o644)
	}
	if ok, err := InListing(dir, "f2999"); !ok || err != nil {
		t.Fatalf("InListing(present) = %v, %v", ok, err)
	}
	if ok, err := InListing(dir, "missing"); ok || err != nil {
		t.Fatalf("InListing(missing) = %v, %v", ok, err)
	}
}
