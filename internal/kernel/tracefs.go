package kernel

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// ErrNoTracefs means the kernel has no tracefs.
var ErrNoTracefs = errors.New("kernel has no tracefs")

// privateMounts is set when this process has a mount namespace of its own.
var privateMounts atomic.Bool

// SetPrivateMounts records that this process runs in a private mount
// namespace (the supervised worker): a tracefs mount made here is invisible
// to the host and disappears with the process, even if it is killed.
func SetPrivateMounts(v bool) { privateMounts.Store(v) }

// tracingDir is tracefs' standard mount point (Linux 4.1+).
const tracingDir = "/sys/kernel/tracing"

// Tracefs returns a tracefs directory, mounting one temporarily if needed.
//
// In a private mount namespace the mount goes on /sys/kernel/tracing when
// nothing is mounted there, and no trace of it can outlive the worker.
// Otherwise (--no-isolation, or an empty mount point is unavailable) it goes
// on a temporary directory, lazily unmounted and removed by the cleanup.
func Tracefs() (string, func(), error) {
	nop := func() {}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return "", nop, err
	}
	defer f.Close()
	var debugfs string
	mounted := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		// "... <mount point> <options> ... - <fstype> <source> <super options>"
		fields := strings.Fields(sc.Text())
		sep := -1
		for i, fld := range fields {
			if fld == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+1 >= len(fields) || len(fields) < 5 {
			continue
		}
		mounted[fields[4]] = true
		switch fields[sep+1] {
		case "tracefs":
			return fields[4], nop, nil
		case "debugfs":
			debugfs = fields[4]
		}
	}
	if debugfs != "" {
		if _, err := os.Stat(filepath.Join(debugfs, "tracing", "enabled_functions")); err == nil {
			return filepath.Join(debugfs, "tracing"), nop, nil
		}
	}

	const flags = unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_RDONLY
	if privateMounts.Load() && !mounted[tracingDir] {
		if st, err := os.Lstat(tracingDir); err == nil && st.IsDir() {
			err := unix.Mount("nodev", tracingDir, "tracefs", flags, "")
			if err == nil {
				return tracingDir, func() { unix.Unmount(tracingDir, unix.MNT_DETACH) }, nil
			}
			if errors.Is(err, unix.ENODEV) {
				return "", nop, ErrNoTracefs
			}
		}
	}

	dir, err := os.MkdirTemp("", "zygarde-tracefs-")
	if err != nil {
		return "", nop, err
	}
	if err := unix.Mount("nodev", dir, "tracefs", flags, ""); err != nil {
		os.Remove(dir)
		if errors.Is(err, unix.ENODEV) {
			return "", nop, ErrNoTracefs
		}
		return "", nop, fmt.Errorf("mounting tracefs: %w", err)
	}
	return dir, func() {
		// Lazy: a reader still holding a file must not keep it mounted.
		unix.Unmount(dir, unix.MNT_DETACH)
		os.Remove(dir)
	}, nil
}
