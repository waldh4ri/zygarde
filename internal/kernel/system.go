package kernel

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

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

// Version returns the kernel build version string (uname -v), which carries
// distribution patch level details (e.g. "#43-Ubuntu SMP ...").
func Version() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return ""
	}
	return unix.ByteSliceToString(u.Version[:])
}

// BootTime reads the system boot timestamp (btime) from /proc/stat.
func BootTime() time.Time {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return time.Time{}
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "btime "); ok {
			if sec, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil && sec > 0 {
				return time.Unix(sec, 0).UTC()
			}
		}
	}
	return time.Time{}
}

// InInitUserNS reports whether the process runs in the initial user namespace.
// Capabilities in a non-initial user namespace do not grant kernel-wide eBPF
// access (capable(CAP_BPF) checks init_user_ns). Reading /proc/self/uid_map
// fails only when user namespaces are compiled out (meaning init_user_ns).
func InInitUserNS() bool {
	data, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return true
	}
	return ParseInitUIDMap(string(data))
}

// ParseInitUIDMap reports whether uid_map content matches the initial user
// namespace ("0 0 4294967295").
func ParseInitUIDMap(s string) bool {
	fields := strings.Fields(s)
	return len(fields) == 3 && fields[0] == "0" && fields[1] == "0" && fields[2] == "4294967295"
}

// LSMContext reads the process's active LSM label (/proc/self/attr/current)
// and reports whether it appears confined by SELinux or AppArmor.
func LSMContext() (label string, confined bool) {
	data, err := os.ReadFile("/proc/self/attr/current")
	if err != nil {
		return "", false
	}
	label = strings.TrimRight(strings.TrimSpace(string(data)), "\x00")
	return label, IsLSMConfined(label)
}

// IsLSMConfined reports whether an LSM label restricts root's normal eBPF access.
func IsLSMConfined(label string) bool {
	if label == "" || label == "unconfined" || strings.HasSuffix(label, "(complain)") {
		return false
	}
	// Standard unconfined / privileged SELinux domains on RHEL, Fedora, SUSE, Debian.
	for _, allow := range []string{"unconfined_t", "kernel_t", "spc_t", "initrc_t", "init_t", "sysadm_t"} {
		if strings.Contains(label, ":"+allow+":") || label == allow {
			return false
		}
	}
	return true
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
	HasCaps bool // CapEff was present and parsed
	Seccomp int  // 0 = disabled, 1 = strict, 2 = filter, -1 = unknown
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
				st.HasCaps = true
			}
		case "Seccomp":
			if v, err := strconv.Atoi(val); err == nil {
				st.Seccomp = v
			}
		}
	}
	return st, sc.Err()
}
