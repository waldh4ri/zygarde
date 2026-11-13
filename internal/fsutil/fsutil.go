// Package fsutil provides safe, forensic-preserving filesystem and process
// helpers: opening untrusted paths without following dangerous symlinks or
// blocking on FIFOs/TTYs (O_NOFOLLOW|O_NONBLOCK|O_NOCTTY), preserving access
// timestamps (O_NOATIME when permitted), capping config reads, resolving paths
// inside container roots (openat2 RESOLVE_IN_ROOT), hashing/preserving
// volatile binaries, and running userspace queries under standard tool names
// ("ps", "ls", "bpftool", "ss", "netstat").
package fsutil

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

// MaxConfig is the default cap for configuration files and scripts. Real
// ones are a few KiB; anything bigger is reported, not silently cut.
const MaxConfig = 4 << 20

// maxHashSize bounds how much of a regular file FileMetadata hashes (64 MiB).
const maxHashSize = 64 << 20

var (
	// ErrNotRegular means the path is not a regular file (a device, FIFO,
	// socket or directory), or is a symlink that was not followed.
	ErrNotRegular = errors.New("not a regular file")
	// ErrTooLarge means the file is larger than the cap the caller set.
	ErrTooLarge = errors.New("file too large")
	// ErrUntrustedLink means a symlink was not followed because a user
	// other than root could have created or replaced it.
	ErrUntrustedLink = errors.New("symlink not owned by root in a root-only directory")
	// ErrListingTooLong means a directory has more than MaxListing entries.
	ErrListingTooLong = errors.New("directory has too many entries to list")
	// ErrNoOpenat2 means the kernel lacks openat2() (Linux 5.6+).
	ErrNoOpenat2 = errors.New("openat2() is not available (Linux 5.6+)")
)

// MaxListing bounds how many entries InListing reads from one directory.
const MaxListing = 1 << 20

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

// ReadFileNoAtime reads a file (such as /proc or /sys pseudo-files or regular
// files) without updating its atime when permitted.
func ReadFileNoAtime(path string) ([]byte, error) {
	f, err := OpenNoAtime(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// ReadDirNoAtime reads directory entries sorted by name without updating atime
// when permitted.
func ReadDirNoAtime(path string) ([]os.DirEntry, error) {
	f, err := OpenDirNoAtime(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

// InListingFile is InListing on a directory that is already open.
func InListingFile(f *os.File, name string) (bool, error) { return inListing(f, name) }

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

// FileMetadata collects forensic attributes (mode, size, uid, gid, inode,
// mtime, ctime and sha256 for regular files) without updating atime or
// following symlinks/opening devices.
func FileMetadata(path string) map[string]string {
	st, err := os.Lstat(path)
	if err != nil {
		return nil
	}
	m := map[string]string{
		"mode":  st.Mode().String(),
		"size":  strconv.FormatInt(st.Size(), 10),
		"mtime": st.ModTime().UTC().Format(time.RFC3339Nano),
	}
	fillStatSys(st, m)
	if st.Mode().IsRegular() && st.Size() >= 0 && st.Size() <= maxHashSize {
		if sum, err := SHA256RegularFile(path); err == nil {
			m["sha256"] = sum
		}
	}
	return m
}

// MergeMetadata copies non-empty metadata keys with an optional prefix into dst.
func MergeMetadata(dst map[string]string, prefix string, meta map[string]string) {
	for k, v := range meta {
		if v != "" {
			dst[prefix+k] = v
		}
	}
}

// SHA256RegularFile hashes a regular file without following symlinks or
// mutating atime.
func SHA256RegularFile(path string) (string, error) {
	f, err := Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxHashSize+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SHA256File computes the hex SHA-256 of path (following magic links such as
// /proc/<pid>/exe) using O_NOATIME.
func SHA256File(path string) (string, error) {
	f, err := OpenNoAtime(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxHashSize+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// PreserveBinary copies a volatile executable (e.g. /proc/<pid>/exe of a
// deleted or memfd-backed process) into dir with mode 0600, returning the
// saved path and its SHA-256 digest.
func PreserveBinary(srcPath, dir, label string) (savedPath, digest string, err error) {
	if dir == "" {
		return "", "", nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("creating preserve dir: %w", err)
	}
	src, err := OpenNoAtime(srcPath)
	if err != nil {
		return "", "", err
	}
	defer src.Close()

	tmp, err := os.CreateTemp(dir, ".preserve-*")
	if err != nil {
		return "", "", err
	}
	tmpName := tmp.Name()
	_ = tmp.Chmod(0o600)

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(src, maxHashSize)); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return "", "", err
	}
	digest = hex.EncodeToString(h.Sum(nil))
	short := digest
	if len(short) > 12 {
		short = short[:12]
	}
	dst := filepath.Join(dir, fmt.Sprintf("%s-%s.bin", sanitize(label), short))
	if err := os.Rename(tmpName, dst); err != nil {
		os.Remove(tmpName)
		return "", digest, err
	}
	return dst, digest, nil
}

func sanitize(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "artifact"
	}
	if len(out) > 48 {
		out = out[:48]
	}
	return string(out)
}

// WithCommVal runs fn on a locked OS thread with its task comm temporarily set
// to comm (on Linux), then restores the previous comm.
func WithCommVal[T any](comm string, fn func() (T, error)) (T, error) {
	var out T
	var err error
	withComm(comm, func() {
		out, err = fn()
	})
	return out, err
}

// WithComm is WithCommVal for functions returning only an error.
func WithComm(comm string, fn func() error) error {
	var err error
	withComm(comm, func() {
		err = fn()
	})
	return err
}
