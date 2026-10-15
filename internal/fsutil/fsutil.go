// Package fsutil opens and reads files under paths that other users may
// control (home directories, /tmp, configuration trees) without being
// tricked into opening something else.
//
// Zygarde runs as root. A plain open() of ~/.bashrc follows a symlink an
// unprivileged user planted there: to /dev/watchdog (opening it arms the
// watchdog, and closing it without the magic write reboots the host), a tape
// device (rewinds), a serial tty (blocks on carrier detect, becomes our
// controlling terminal), /dev/urandom (never ends), or a FIFO (blocks
// forever). Everything here opens with O_NOFOLLOW|O_NONBLOCK|O_NOCTTY,
// accepts regular files only, and caps how much is read.
package fsutil

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// MaxConfig is the default cap for configuration files and scripts. Real
// ones are a few KiB; anything bigger is reported, not silently cut.
const MaxConfig = 4 << 20

var (
	// ErrNotRegular means the path is not a regular file (a device, FIFO,
	// socket or directory), or is a symlink that was not followed.
	ErrNotRegular = errors.New("not a regular file")
	// ErrTooLarge means the file is larger than the cap the caller set.
	ErrTooLarge = errors.New("file too large")
	// ErrUntrustedLink means a symlink was not followed because a user
	// other than root could have created or replaced it.
	ErrUntrustedLink = errors.New("symlink not owned by root in a root-only directory")
)

const openFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_CLOEXEC

// Open opens path for reading if it is a regular file. A symlink as the
// last component is never followed (ErrNotRegular). Directories above it
// are resolved normally: callers only pass paths whose parents are owned
// by root (or by the user the file belongs to).
func Open(path string) (*os.File, error) {
	fd, err := unix.Open(path, openFlags, 0)
	if errors.Is(err, unix.ELOOP) {
		return nil, &os.PathError{Op: "open", Path: path, Err: ErrNotRegular}
	}
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return checkRegular(fd, path)
}

func checkRegular(fd int, path string) (*os.File, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, &os.PathError{Op: "fstat", Path: path, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, &os.PathError{Op: "open", Path: path, Err: ErrNotRegular}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// maxLinks bounds how many trusted symlinks OpenSystem follows.
const maxLinks = 8

// OpenSystem is Open for system configuration, where packages legitimately
// symlink files (/etc/rc.local -> rc.d/rc.local, modules-load.d entries
// pointing into /usr/lib). A symlink is followed only if it is owned by
// root and sits in a directory owned by root that nobody else can write,
// so only root could have placed it.
func OpenSystem(path string) (*os.File, error) {
	for i := 0; ; i++ {
		f, err := Open(path)
		if !errors.Is(err, ErrNotRegular) {
			return f, err
		}
		var st unix.Stat_t
		if lerr := unix.Lstat(path, &st); lerr != nil || st.Mode&unix.S_IFMT != unix.S_IFLNK {
			return nil, err // not a symlink: a device, FIFO, socket or directory
		}
		if i >= maxLinks {
			return nil, &os.PathError{Op: "open", Path: path, Err: unix.ELOOP}
		}
		if !TrustedLink(path, st) {
			return nil, &os.PathError{Op: "open", Path: path, Err: ErrUntrustedLink}
		}
		target, rerr := os.Readlink(path)
		if rerr != nil {
			return nil, rerr
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}
		path = target
	}
}

// TrustedLink reports whether only root could have created the symlink at
// path (whose lstat is st): it is owned by root, and so is its directory,
// which no one else can write to.
func TrustedLink(path string, st unix.Stat_t) bool {
	if st.Uid != 0 {
		return false
	}
	var dir unix.Stat_t
	if err := unix.Stat(filepath.Dir(path), &dir); err != nil {
		return false
	}
	return dir.Uid == 0 && dir.Mode&0o022 == 0
}

// ReadAll reads f up to max bytes. It returns ErrTooLarge, with the first
// max bytes, if there is more.
func ReadAll(f *os.File, max int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return data, err
	}
	if int64(len(data)) > max {
		return data[:max], fmt.Errorf("%s: %w (over %d bytes)", f.Name(), ErrTooLarge, max)
	}
	return data, nil
}

// ReadFile opens path with Open and reads at most max bytes.
func ReadFile(path string, max int64) ([]byte, error) {
	f, err := Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadAll(f, max)
}

// ReadSystemFile opens path with OpenSystem and reads at most max bytes.
func ReadSystemFile(path string, max int64) ([]byte, error) {
	f, err := OpenSystem(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadAll(f, max)
}

// MaxLine is the longest line NewScanner accepts. It is as large as
// MaxConfig, so a file read within that cap can't overflow it.
const MaxLine = MaxConfig

// NewScanner returns a line scanner that accepts lines up to MaxLine. The
// default 64 KiB limit makes bufio.Scanner stop at a long line and report it
// only through Err(): one padded line would hide everything after it.
// Callers must check Err().
func NewScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), MaxLine+1)
	return sc
}

// Owner returns the owner of an open file.
func Owner(f *os.File) (uint32, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return 0, err
	}
	return st.Uid, nil
}

// MaxListing bounds how many entries InListing reads from one directory.
const MaxListing = 1 << 20

// ErrListingTooLong means a directory has more than MaxListing entries.
var ErrListingTooLong = errors.New("directory has too many entries to list")

// InListing reports whether name appears in the listing of dir. It streams
// the directory in batches and stops at the first match, so a directory
// with millions of entries costs neither memory nor much time; past
// MaxListing entries it gives up with ErrListingTooLong.
func InListing(dir, name string) (bool, error) {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, &os.PathError{Op: "open", Path: dir, Err: err}
	}
	f := os.NewFile(uintptr(fd), dir)
	defer f.Close()
	return inListing(f, name)
}

func inListing(f *os.File, name string) (bool, error) {
	read := 0
	for {
		// Readdirnames doesn't lstat entries, unlike ReadDir on some filesystems.
		names, err := f.Readdirnames(1024)
		for _, n := range names {
			if n == name {
				return true, nil
			}
		}
		read += len(names)
		if errors.Is(err, io.EOF) || (err == nil && len(names) == 0) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if read > MaxListing {
			return false, ErrListingTooLong
		}
	}
}
