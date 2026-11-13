// Package canary plants known objects that Cells must find in every view
// they compare. If a canary is missing from a view, that view is being
// filtered and its "clean" answers can't be trusted.
package canary

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// RoleEnv selects what a re-executed zygarde binary does.
const RoleEnv = "ZYGARDE_ROLE"

// ParentEnv holds the PID of the zygarde process that set RoleEnv. A role
// is only honoured when it matches the actual parent, so a ZYGARDE_ROLE
// left in the operator's environment (sudo -E) can't turn the command the
// operator runs into a canary or a worker.
const ParentEnv = "ZYGARDE_PARENT"

// TagEnv carries a per-scan random prefix for canary files so their names do
// not contain "zygarde" while still letting the supervisor clean up if a
// worker is killed mid-check.
const TagEnv = "ZYGARDE_TAG"

// RoleProcess is the role of a canary process.
const RoleProcess = "canary"

var (
	tagOnce sync.Once
	scanTag string
)

// ScanTag returns the random tag for this scan, inheriting TagEnv if set.
func ScanTag() string {
	tagOnce.Do(func() {
		if v := os.Getenv(TagEnv); len(v) >= 6 {
			scanTag = v
			return
		}
		scanTag = Token()[:8]
	})
	return scanTag
}

// ChildEnv returns the environment for re-executing zygarde with a role:
// the current environment without inherited role variables, plus the role,
// this process's PID as the parent, the scan tag, and extra variables.
func ChildEnv(role string, extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, RoleEnv+"=") || strings.HasPrefix(kv, ParentEnv+"=") || strings.HasPrefix(kv, TagEnv+"=") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, RoleEnv+"="+role, ParentEnv+"="+strconv.Itoa(os.Getpid()), TagEnv+"="+ScanTag())
	return append(env, extra...)
}

// Role returns the role this process was started with by its zygarde
// parent, or "" for a process the operator started.
func Role() string {
	role := os.Getenv(RoleEnv)
	if role == "" || os.Getenv(ParentEnv) != strconv.Itoa(os.Getppid()) {
		return ""
	}
	return role
}

// Token returns a random hex string to make canary names unpredictable.
func Token() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// ProgName returns an unpredictable BPF object name (<= 15 chars, [a-z]) so
// rootkits cannot allowlist a hardcoded canary name like "zyg_canary".
func ProgName() string {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = 'a' + (v % 26)
	}
	return string(out)
}

// Process is a child process that exists only to be found.
type Process struct {
	cmd   *exec.Cmd
	stdin io.Closer
}

// StartProcess re-executes the current binary as an idle canary process.
// It exits when Stop is called or when its parent dies (stdin closes).
func StartProcess() (*Process, error) {
	cmd := exec.Command("/proc/self/exe")
	cmd.Env = ChildEnv(RoleProcess)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting canary process: %w", err)
	}
	return &Process{cmd: cmd, stdin: stdin}, nil
}

// PID returns the canary's process ID.
func (p *Process) PID() int { return p.cmd.Process.Pid }

// Stop terminates the canary and reaps it.
func (p *Process) Stop() {
	p.stdin.Close()
	_ = p.cmd.Process.Kill()
	_ = p.cmd.Wait()
}

// RunProcess is the body of a canary process: wait until stdin closes.
func RunProcess() {
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

// ActiveFileDir prefers /dev/shm (in-RAM tmpfs, avoiding on-disk /tmp mtime
// updates) when available, falling back to FileDir.
func ActiveFileDir() string {
	if st, err := os.Stat("/dev/shm"); err == nil && st.IsDir() {
		return "/dev/shm"
	}
	return FileDir
}

// FileDir is the fallback temporary directory for canary files.
const FileDir = "/tmp"

// FilePrefix is the name prefix of canary files created by process pid.
func FilePrefix(pid int) string {
	return fmt.Sprintf("tmp-%s-%d-", ScanTag(), pid)
}

// RemoveFiles deletes canary files in dir (and /dev/shm) left behind by
// process pid, e.g. because it was killed before it could clean up.
func RemoveFiles(dir string, pid int) {
	for _, d := range []string{dir, "/dev/shm"} {
		if d == "" {
			continue
		}
		for _, pat := range []string{
			filepath.Join(d, FilePrefix(pid)+"*"),
			filepath.Join(d, fmt.Sprintf("zygarde-canary-%d-*", pid)),
		} {
			matches, _ := filepath.Glob(pat)
			for _, m := range matches {
				os.Remove(m)
			}
		}
	}
}

// RemoveStale deletes canary files in dir (and /dev/shm) left behind by dead
// processes older than ten minutes. Only root-owned regular files are removed.
func RemoveStale(dir string) {
	old := time.Now().Add(-10 * time.Minute).Unix()
	for _, d := range []string{dir, "/dev/shm"} {
		if d == "" {
			continue
		}
		for _, pat := range []string{
			filepath.Join(d, "zygarde-canary-*-*"),
			filepath.Join(d, "tmp-*-*-*"),
		} {
			matches, _ := filepath.Glob(pat)
			for _, m := range matches {
				pid := parseCanaryPID(filepath.Base(m))
				if pid <= 0 || !errors.Is(unix.Kill(pid, 0), unix.ESRCH) {
					continue
				}
				var st unix.Stat_t
				if unix.Lstat(m, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Uid == 0 && st.Mtim.Sec < old {
					os.Remove(m)
				}
			}
		}
	}
}

func parseCanaryPID(base string) int {
	var pid int
	if _, err := fmt.Sscanf(base, "zygarde-canary-%d-", &pid); err == nil && pid > 0 {
		return pid
	}
	// "tmp-<8hex>-<pid>-<12hex>"
	parts := strings.Split(base, "-")
	if len(parts) == 4 && parts[0] == "tmp" && len(parts[1]) == 8 {
		if n, err := strconv.Atoi(parts[2]); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

// File is a temporary file that exists only to be found.
type File struct {
	Dir  string
	Path string
}

// CreateFile creates a canary file in dir.
func CreateFile(dir string) (*File, error) {
	path := filepath.Join(dir, FilePrefix(os.Getpid())+Token())
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return nil, err
	}
	return &File{Dir: dir, Path: path}, nil
}

// Touch opens and closes the file so that open syscalls see it.
func (f *File) Touch() error {
	fd, err := os.Open(f.Path)
	if err != nil {
		return err
	}
	return fd.Close()
}

// Remove deletes the canary file.
func (f *File) Remove() { os.Remove(f.Path) }
