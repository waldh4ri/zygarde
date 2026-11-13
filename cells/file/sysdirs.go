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
		if st.Mode().IsRegular() && st.Size() > 0 && st.Size() <= maxContentBytes {
			if b, err := fsutil.ReadFileNoAtime(path); err == nil && printable(b) {
				details["content"] = strings.TrimSpace(string(b))
			}
		}
		// A dot-entry that holds no executable still stands out in a directory
		// of programs, or when anyone can write it: HiddenWasp keeps the path of
		// its preloaded library in a world-writable /usr/sbin/.ifup-local.
		worldWritable := st.Mode().Perm()&0o002 != 0
		if len(exes) == 0 && !binDir(dir) && !worldWritable {
			rec.Observe(fmt.Sprintf("Hidden entry %s in a system directory", path), details)
			continue
		}
		suspicious++
		desc := fmt.Sprintf("Hidden %s %s in a system directory holds %d executable(s)", kindOf(st), path, len(exes))
		if len(exes) == 0 {
			desc = fmt.Sprintf("Hidden %s %s in a system directory", kindOf(st), path)
			if worldWritable {
				desc += " is writable by everyone"
			}
		} else {
			details["executables"] = strings.Join(truncated(exes, 10), ", ")
			fsutil.MergeMetadata(details, "first_exe_", fsutil.FileMetadata(exes[0]))
		}
		rec.Suspicious(core.Finding{
			Description: desc,
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

// maxContentBytes bounds how much of a small hidden file is quoted in a finding.
const maxContentBytes = 256

// binDir reports whether dir only holds programs: packages ship no dot-entries
// there, executable or not.
func binDir(dir string) bool {
	switch dir {
	case "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin":
		return true
	}
	return false
}

// printable reports whether b is plain text (no control bytes except newline
// and tab), safe to quote in a report.
func printable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 && c != '\n' && c != '\t' || c == 0x7f {
			return false
		}
	}
	return true
}

func kindOf(st fs.FileInfo) string {
	if st.IsDir() {
		return "directory"
	}
	return "file"
}

// executablesUnder lists executable regular files below dir, without
// following symbolic links, within the walk limits and using O_NOATIME.
func executablesUnder(dir string) []string {
	var out []string
	seen := 0
	var walk func(cur string, depth int)
	walk = func(cur string, depth int) {
		if depth > maxWalkDepth || seen > maxWalkEntries {
			return
		}
		entries, err := fsutil.ReadDirNoAtime(cur)
		if err != nil {
			return
		}
		for _, d := range entries {
			if seen++; seen > maxWalkEntries {
				return
			}
			p := filepath.Join(cur, d.Name())
			if d.IsDir() {
				walk(p, depth+1)
				continue
			}
			if !d.Type().IsRegular() {
				continue
			}
			if st, err := d.Info(); err == nil && isExecutable(p, st) {
				out = append(out, p)
			}
		}
	}
	walk(dir, 1)
	return out
}

// isExecutable reports whether a regular file has an execute bit or is an
// ELF object (shared libraries are often not marked executable).
func isExecutable(path string, st fs.FileInfo) bool {
	if st.Mode().Perm()&0o111 != 0 {
		return true
	}
	// fsutil.Open refuses symlinks, FIFOs and devices and uses O_NOATIME.
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
