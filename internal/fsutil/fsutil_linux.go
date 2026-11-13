//go:build linux

package fsutil

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const safeOpenFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_CLOEXEC

func openWithOptionalNoAtime(path string, flags int) (int, error) {
	fd, err := unix.Open(path, flags|unix.O_NOATIME, 0)
	if errors.Is(err, unix.EPERM) {
		fd, err = unix.Open(path, flags, 0)
	}
	return fd, err
}

// Open opens path for reading if it is a regular file (without following a
// final symlink, blocking on FIFOs/TTYs, or updating atime when permitted).
func Open(path string) (*os.File, error) {
	fd, err := openWithOptionalNoAtime(path, safeOpenFlags)
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
// root and sits in a directory owned by root that nobody else can write.
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

// Owner returns the owner UID of an open file.
func Owner(f *os.File) (uint32, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return 0, err
	}
	return st.Uid, nil
}

// InListing reports whether name appears in the listing of dir. It streams
// the directory in batches with O_NOATIME and stops at the first match.
func InListing(dir, name string) (bool, error) {
	f, err := OpenDirNoAtime(dir)
	if err != nil {
		return false, err
	}
	defer f.Close()
	return inListing(f, name)
}

// OpenNoAtime opens path read-only with O_NOATIME when permitted, falling back
// without O_NOATIME on EPERM. Unlike Open, it follows magic symlinks such as
// /proc/<pid>/exe and accepts procfs/sysfs files.
func OpenNoAtime(path string) (*os.File, error) {
	fd, err := openWithOptionalNoAtime(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// OpenDirNoAtime opens a directory with O_DIRECTORY|O_NONBLOCK|O_NOCTTY and
// O_NOATIME when permitted, so FIFOs or device nodes placed where a directory
// is expected never block or open.
func OpenDirNoAtime(path string) (*os.File, error) {
	fd, err := openWithOptionalNoAtime(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

func fillStatSys(st fs.FileInfo, m map[string]string) {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys == nil {
		return
	}
	m["inode"] = strconv.FormatUint(sys.Ino, 10)
	m["uid"] = strconv.FormatUint(uint64(sys.Uid), 10)
	m["gid"] = strconv.FormatUint(uint64(sys.Gid), 10)
	ctime := time.Unix(int64(sys.Ctim.Sec), int64(sys.Ctim.Nsec)).UTC()
	m["ctime"] = ctime.Format(time.RFC3339Nano)
}

func withComm(comm string, fn func()) {
	if comm == "" {
		fn()
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var prev [16]byte
	gotPrev := unix.Prctl(unix.PR_GET_NAME, uintptr(unsafe.Pointer(&prev[0])), 0, 0, 0) == nil

	var next [16]byte
	copy(next[:15], comm)
	if unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(&next[0])), 0, 0, 0) == nil && gotPrev {
		defer func() {
			_ = unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(&prev[0])), 0, 0, 0)
		}()
	}
	fn()
}
