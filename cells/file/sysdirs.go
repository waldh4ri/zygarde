package file

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fsutil"
)

// systemDirs are the binary and library directories that hold no
// dot-entries on a stock install.
func systemDirs() []string {
	dirs := []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin"}
	for _, pattern := range []string{"/lib*", "/usr/lib*"} {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			if st, err := os.Stat(m); err == nil && st.IsDir() {
				dirs = append(dirs, m)
			}
		}
	}
	return dirs
}

// allowedDotEntry reports dot-entries that distribution packages ship in
// system directories.
func allowedDotEntry(name string) bool {
	switch {
	case name == ".build-id": // debuginfo links (Fedora, RHEL, SUSE)
		return true
	case strings.HasSuffix(name, ".hmac"): // FIPS integrity checksums (RHEL, SUSE)
		return true
	case strings.HasPrefix(name, ".keep"): // placeholder files (Gentoo)
		return true
	}
	return false
}

// Limits on how much of a dot-directory is searched for executables.
const (
	maxWalkDepth   = 4
	maxWalkEntries = 2000
)

// dotEntries checks the dot-entries of one system directory. names are the
// entries a listing of dir produced. seen holds directories already checked
// under another path (e.g. /lib, a symlink to /usr/lib).
func dotEntries(rec *core.Recorder, dir string, names map[string]bool, seen map[string]bool) int {
	real, err := filepath.EvalSymlinks(dir)
	if err != nil || seen[real] {
		return 0
	}
	seen[real] = true

	var dots []string
	for n := range names {
		if strings.HasPrefix(n, ".") && n != "." && n != ".." && !allowedDotEntry(n) {
			dots = append(dots, n)
		}
	}
	sort.Strings(dots)

	// Report the canonical path: /usr/bin/.x rather than /bin/.x when /bin
	// is a symlink to /usr/bin.
	dir = real
	suspicious := 0
	for _, n := range dots {
		path := filepath.Join(dir, n)
		st, err := os.Lstat(path)
		if err != nil {
			continue
		}
		details := map[string]string{"path": path, "directory": dir, "mode": st.Mode().String()}
		var exes []string
		if st.IsDir() {
			exes = executablesUnder(path)
		} else if st.Mode().IsRegular() && isExecutable(path, st) {
			exes = []string{path}
		}
		if len(exes) == 0 {
			rec.Observe(fmt.Sprintf("Hidden entry %s in a system directory", path), details)
			continue
		}
		suspicious++
		details["executables"] = strings.Join(truncated(exes, 10), ", ")
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("Hidden %s %s in a system directory holds %d executable(s)", kindOf(st), path, len(exes)),
			Details:     details,
			Why: "Binary and library directories hold no dot-entries on a stock install, and ls hides them by " +
				"default. Rootkits stash trojaned tools there (e.g. a fake sudo under /usr/bin/.local) so they " +
				"sit next to the real ones without showing up.",
			Benign: "A package or local tool that keeps helpers in a dot-directory. Check which package owns the " +
				"files (dpkg -S, rpm -qf).",
		})
	}
	return suspicious
}

func kindOf(st fs.FileInfo) string {
	if st.IsDir() {
		return "directory"
	}
	return "file"
}

// executablesUnder lists executable regular files below dir, without
// following symbolic links, within the walk limits.
func executablesUnder(dir string) []string {
	var out []string
	seen := 0
	base := strings.Count(dir, string(filepath.Separator))
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if seen++; seen > maxWalkEntries {
			return filepath.SkipAll
		}
		if d.IsDir() {
			if strings.Count(path, string(filepath.Separator))-base >= maxWalkDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if st, err := d.Info(); err == nil && isExecutable(path, st) {
			out = append(out, path)
		}
		return nil
	})
	return out
}

// isExecutable reports whether a regular file has an execute bit or is an
// ELF object (shared libraries are often not marked executable).
func isExecutable(path string, st fs.FileInfo) bool {
	if st.Mode().Perm()&0o111 != 0 {
		return true
	}
	// Not os.Open: the entry may have been swapped for a FIFO or a device
	// symlink since it was listed.
	f, err := fsutil.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil {
		return false
	}
	return bytes.Equal(magic, []byte("\x7fELF"))
}

func truncated(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(s[:n:n], fmt.Sprintf("… (%d more)", len(s)-n))
}
