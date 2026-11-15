package userhooks

import (
	"context"
	"debug/elf"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fsutil"
)

// privBinDirs hold setuid and setgid programs: the binary directories are read
// flat, the library directories (helpers such as dbus-daemon-launch-helper,
// polkit-agent-helper-1, ssh-keysign) down to privLibDepth levels.
var (
	privBinDirs  = []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"}
	privLibDirs  = []string{"/usr/lib", "/usr/lib64", "/usr/libexec", "/usr/local/lib", "/usr/local/libexec", "/lib", "/lib64"}
	privLibDepth = 3
)

// maxPrivFiles bounds the entries examined in the library directories.
const maxPrivFiles = 400000

// privBinary is a setuid or setgid ELF program with a library search path.
type privBinary struct {
	path, tag, value string
}

// checkSetuidSearchPaths flags setuid and setgid programs whose RPATH or
// RUNPATH lets an unprivileged user supply the libraries they load. In secure
// mode the dynamic linker ignores LD_LIBRARY_PATH and LD_PRELOAD but still
// honours the search path recorded in the binary, so a relative or writable
// directory there turns the program into a root shell for whoever controls it.
func (c *Cell) checkSetuidSearchPaths(ctx context.Context, rec *core.Recorder) (int, error) {
	bins, truncated, err := c.privilegedSearchPaths(ctx)
	if err != nil {
		return 0, err
	}
	if truncated {
		rec.Limit("Setuid programs: more than %d files under the library directories, the rest were not examined", maxPrivFiles)
	}
	n := 0
	for _, b := range bins {
		for _, entry := range filepath.SplitList(b.value) {
			why := c.searchDirRisk(filepath.Dir(b.path), entry)
			if why == "" {
				continue
			}
			n++
			d := map[string]string{"program": b.path, "tag": b.tag, "search_path": b.value, "entry": entry, "reason": why}
			fsutil.MergeMetadata(d, "file_", fsutil.FileMetadata(c.path(b.path)))
			rec.Suspicious(core.Finding{
				Description: fmt.Sprintf("Setuid/setgid program %s searches %q for libraries (%s): %s", b.path, entry, b.tag, why),
				Details:     d,
				Why: "The dynamic linker runs a setuid or setgid program in secure mode: it ignores LD_PRELOAD and " +
					"LD_LIBRARY_PATH, but still loads libraries from the RPATH or RUNPATH written into the binary. An entry " +
					"that an unprivileged user can fill (relative to the current directory, or a directory they can write) " +
					"lets them run code with the program's privileges: a planted privilege escalation backdoor.",
				Benign: "A badly packaged local program. Check which package owns it (dpkg -S, rpm -qf) and whether the setuid " +
					"bit is needed.",
			})
		}
	}
	return n, nil
}

// privilegedSearchPaths lists the setuid and setgid ELF programs that carry an
// RPATH or RUNPATH.
func (c *Cell) privilegedSearchPaths(ctx context.Context) ([]privBinary, bool, error) {
	var out []privBinary
	seen := map[[2]uint64]bool{} // device and inode: /bin and /usr/bin are often the same directory
	examined, truncated := 0, false
	visit := func(p string, d fs.DirEntry) {
		if !d.Type().IsRegular() {
			return
		}
		var st unix.Stat_t
		if unix.Lstat(p, &st) != nil || st.Mode&(unix.S_ISUID|unix.S_ISGID) == 0 {
			return
		}
		key := [2]uint64{uint64(st.Dev), st.Ino}
		if seen[key] {
			return
		}
		seen[key] = true
		for _, b := range readSearchPaths(p) {
			b.path = c.rel(p)
			out = append(out, b)
		}
	}
	for _, dir := range privBinDirs {
		entries, err := fsutil.ReadDirNoAtime(c.path(dir))
		if err != nil {
			continue
		}
		for _, e := range entries {
			visit(filepath.Join(c.path(dir), e.Name()), e)
		}
	}
	walked := map[[2]uint64]bool{}
	for _, dir := range privLibDirs {
		root := c.path(dir)
		var st unix.Stat_t
		if unix.Stat(root, &st) != nil || walked[[2]uint64{uint64(st.Dev), st.Ino}] {
			continue // missing, or the same directory as one already walked (/lib -> /usr/lib)
		}
		walked[[2]uint64{uint64(st.Dev), st.Ino}] = true
		depth := strings.Count(filepath.Clean(root), string(filepath.Separator))
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if d.IsDir() {
				if strings.Count(p, string(filepath.Separator))-depth >= privLibDepth {
					return filepath.SkipDir
				}
				return nil
			}
			if examined++; examined > maxPrivFiles {
				truncated = true
				return filepath.SkipAll
			}
			visit(p, d)
			return nil
		})
		if err != nil && ctx.Err() != nil {
			return nil, truncated, ctx.Err()
		}
		if truncated {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path+out[i].tag < out[j].path+out[j].tag })
	return out, truncated, nil
}

// readSearchPaths returns the DT_RPATH and DT_RUNPATH strings of an ELF file.
func readSearchPaths(p string) []privBinary {
	f, err := fsutil.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	ef, err := elf.NewFile(f)
	if err != nil {
		return nil
	}
	defer ef.Close()
	var out []privBinary
	for _, t := range []struct {
		tag  elf.DynTag
		name string
	}{{elf.DT_RPATH, "RPATH"}, {elf.DT_RUNPATH, "RUNPATH"}} {
		vals, err := ef.DynString(t.tag)
		if err != nil {
			return out
		}
		for _, v := range vals {
			out = append(out, privBinary{tag: t.name, value: v})
		}
	}
	return out
}

// searchDirRisk says why an RPATH/RUNPATH entry of a privileged program in
// binDir can be controlled by an unprivileged user, or returns "".
func (c *Cell) searchDirRisk(binDir, entry string) string {
	switch {
	case entry == "":
		return "an empty entry, which means the current directory of whoever runs it"
	case strings.HasPrefix(entry, "$ORIGIN") || strings.HasPrefix(entry, "${ORIGIN}"):
		// Expanded to the program's own directory (secure mode only keeps the
		// result if it is a trusted directory, but check it anyway).
		rest := strings.TrimPrefix(strings.TrimPrefix(entry, "${ORIGIN}"), "$ORIGIN")
		entry = filepath.Join(binDir, rest)
	case strings.Contains(entry, "$"):
		return "" // $LIB and $PLATFORM expand to fixed system names
	case !strings.HasPrefix(entry, "/"):
		return "a relative directory, resolved from the current directory of whoever runs it"
	}
	if why := c.unusualDir(entry, ""); why != "" {
		return "it is " + why
	}
	return fsutil.ControlledBy(c.root, filepath.Clean(entry))
}

// rel turns a path under c.root back into the scanned system's path.
func (c *Cell) rel(p string) string {
	if c.root == "" {
		return p
	}
	r, err := filepath.Rel(c.root, p)
	if err != nil {
		return p
	}
	return "/" + filepath.ToSlash(r)
}
