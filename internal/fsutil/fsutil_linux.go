//go:build linux

package fsutil

import (
	"errors"
	"io/fs"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// OpenNoAtime opens path read-only with O_NOATIME when permitted, falling back
// to a plain open when the caller does not own the file and lacks CAP_FOWNER.
func OpenNoAtime(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOATIME, 0)
	if errors.Is(err, unix.EPERM) {
		return os.Open(path)
	}
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

func openDirNoAtime(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOATIME, 0)
	if errors.Is(err, unix.EPERM) {
		return os.Open(path)
	}
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
