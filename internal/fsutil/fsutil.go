// Package fsutil provides forensic-safe filesystem and process helpers:
// reading directories and files without mutating access timestamps (O_NOATIME),
// collecting file hashes and stat metadata, preserving volatile binaries, and
// running userspace queries under standard tool names (ps, ls, bpftool, ss) to
// trigger comm-filtering rootkits.
package fsutil

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

// maxHashSize bounds how much of a regular file FileMetadata hashes (64 MiB).
const maxHashSize = 64 << 20

// ReadFileNoAtime reads a file without updating its atime when permitted.
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
	f, err := openDirNoAtime(path)
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

// FileMetadata collects forensic attributes (mode, size, uid, gid, inode,
// mtime, ctime and sha256 for regular files) without updating atime.
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
		if sum, err := SHA256File(path); err == nil {
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

// SHA256File computes the hex SHA-256 of path using O_NOATIME.
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
// to comm (on Linux), then restores the previous comm. Rootkits that filter
// syscalls only for tools like "ps", "ls", "bpftool", "ss" or "netstat" reveal
// their filtering when queried under those names.
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
