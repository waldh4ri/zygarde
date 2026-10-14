// Package canary plants known objects that Cells must find in every view
// they compare. If a canary is missing from a view, that view is being
// filtered and its "clean" answers can't be trusted.
package canary

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// RoleEnv selects what a re-executed zygarde binary does.
const RoleEnv = "ZYGARDE_ROLE"

// RoleProcess is the role of a canary process.
const RoleProcess = "canary"

// Token returns a random hex string to make canary names unpredictable.
func Token() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
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
	cmd.Env = append(os.Environ(), RoleEnv+"="+RoleProcess)
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

// FileDir is where canary files are created. It must be one of the
// directories the hidden file Cell watches.
const FileDir = "/tmp"

// FilePrefix is the name prefix of canary files created by process pid.
func FilePrefix(pid int) string { return fmt.Sprintf("zygarde-canary-%d-", pid) }

// RemoveFiles deletes canary files in dir left behind by process pid, e.g.
// because it was killed before it could clean up.
func RemoveFiles(dir string, pid int) {
	matches, _ := filepath.Glob(filepath.Join(dir, FilePrefix(pid)+"*"))
	for _, m := range matches {
		os.Remove(m)
	}
}

// File is a temporary file that exists only to be found.
type File struct {
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
	return &File{Path: path}, nil
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
