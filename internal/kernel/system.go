package kernel

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Capability bits from include/uapi/linux/capability.h.
const (
	CapSysAdmin = 21
	CapPerfmon  = 38
	CapBPF      = 39
)

// Release returns the kernel release (uname -r).
func Release() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "unknown"
	}
	return unix.ByteSliceToString(u.Release[:])
}

// Lockdown returns the active kernel lockdown mode ("none", "integrity",
// "confidentiality"), or "" if the lockdown LSM is not present.
func Lockdown() string {
	data, err := os.ReadFile("/sys/kernel/security/lockdown")
	if err != nil {
		return ""
	}
	return ParseLockdown(string(data))
}

// ParseLockdown extracts the bracketed mode from e.g. "none [integrity] confidentiality".
func ParseLockdown(s string) string {
	start := strings.IndexByte(s, '[')
	end := strings.IndexByte(s, ']')
	if start < 0 || end <= start {
		return ""
	}
	return s[start+1 : end]
}

// ProcStatus holds the fields of /proc/self/status that matter for eBPF.
type ProcStatus struct {
	CapEff  uint64
	Seccomp int // 0 = disabled, 1 = strict, 2 = filter, -1 = unknown
}

// HasCap reports whether capability bit c is in the effective set.
func (s ProcStatus) HasCap(c uint) bool { return s.CapEff&(1<<c) != 0 }

// SelfStatus reads /proc/self/status.
func SelfStatus() (ProcStatus, error) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return ProcStatus{Seccomp: -1}, err
	}
	defer f.Close()
	return ParseStatus(f)
}

// ParseStatus parses /proc/<pid>/status content.
func ParseStatus(r io.Reader) (ProcStatus, error) {
	st := ProcStatus{Seccomp: -1}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch key {
		case "CapEff":
			if v, err := strconv.ParseUint(val, 16, 64); err == nil {
				st.CapEff = v
			}
		case "Seccomp":
			if v, err := strconv.Atoi(val); err == nil {
				st.Seccomp = v
			}
		}
	}
	return st, sc.Err()
}
