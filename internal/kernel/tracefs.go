package kernel

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// ErrNoTracefs means the kernel has no tracefs.
var ErrNoTracefs = errors.New("kernel has no tracefs")

// Tracefs returns a tracefs directory, mounting one temporarily if needed.
func Tracefs() (string, func(), error) {
	nop := func() {}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return "", nop, err
	}
	defer f.Close()
	var debugfs string
	sc := bufio.NewScanner(f)
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

	dir, err := os.MkdirTemp("", "zygarde-tracefs-")
	if err != nil {
		return "", nop, err
	}
	if err := unix.Mount("nodev", dir, "tracefs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC|unix.MS_RDONLY, ""); err != nil {
		os.Remove(dir)
		if errors.Is(err, unix.ENODEV) {
			return "", nop, ErrNoTracefs
		}
		return "", nop, fmt.Errorf("mounting tracefs: %w", err)
	}
	return dir, func() {
		unix.Unmount(dir, 0)
		os.Remove(dir)
	}, nil
}
