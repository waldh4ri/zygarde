package fsutil

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// ErrNoOpenat2 means the kernel lacks openat2() (Linux 5.6+).
var ErrNoOpenat2 = errors.New("openat2() is not available (Linux 5.6+)")

// OpenInRoot opens path as if root were "/": absolute symlinks and ".."
// resolve inside root (openat2 RESOLVE_IN_ROOT). This is how a path must
// be looked up in another mount namespace through /proc/<pid>/root, where a
// plain open would resolve the image's absolute symlinks against the host.
// flags are open(2) flags; O_CLOEXEC is added, and with O_PATH the last
// component is not followed unless the caller omits O_NOFOLLOW.
func OpenInRoot(root, path string, flags int) (*os.File, error) {
	rfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: root, Err: err}
	}
	defer unix.Close(rfd)
	how := unix.OpenHow{
		Flags:   uint64(flags | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := unix.Openat2(rfd, path, &how)
	if errors.Is(err, unix.ENOSYS) {
		return nil, ErrNoOpenat2
	}
	if err != nil {
		return nil, &os.PathError{Op: "openat2", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// SameAsHostRoot reports whether dir is the same directory as "/" (for
// /proc/<pid>/root: the process shares the host's root).
func SameAsHostRoot(dir string) bool {
	var a, b unix.Stat_t
	if unix.Stat(dir, &a) != nil || unix.Stat("/", &b) != nil {
		return false
	}
	return a.Dev == b.Dev && a.Ino == b.Ino
}

// InListingFile is InListing on a directory that is already open.
func InListingFile(f *os.File, name string) (bool, error) { return inListing(f, name) }
