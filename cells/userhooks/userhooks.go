// Package userhooks detects libraries injected into processes through the
// dynamic linker: /etc/ld.so.preload, unusual library directories and
// LD_PRELOAD.
package userhooks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fsutil"
)

// Cell looks for userland rootkits that hook libc through the dynamic linker.
//
// Zygarde itself is a static binary that makes syscalls directly, so these
// hooks can't hide anything from it, and the kernel-side comparisons stay
// clean while libc lies to every other program. This Cell reports the
// injection points instead (the same ones Elastic and Sandfly treat as
// primary signals). LinkPro falls back to /etc/ld.so.preload when its eBPF
// module can't load.
type Cell struct {
	root string // prefixes system paths (tests use a fixture tree)
	proc string
}

// New returns the userspace hook Cell.
func New() *Cell { return &Cell{proc: "/proc"} }

func (*Cell) ID() string                    { return "userspace_hooks" }
func (*Cell) Name() string                  { return "Userspace Hook Detection" }
func (*Cell) Timeout() time.Duration        { return 30 * time.Second }
func (*Cell) Supported(env *core.Env) error { return nil }
func (*Cell) Description() string {
	return "Checks dynamic linker injection points: /etc/ld.so.preload, ld.so.conf library directories and LD_PRELOAD in process environments"
}

func (c *Cell) Run(ctx context.Context, env *core.Env, rec *core.Recorder) error {
	suspicious := 0
	suspicious += c.checkPreloadFile(rec)
	suspicious += c.checkLdSoConf(rec)
	n, err := c.checkEnvironments(ctx, rec)
	if err != nil {
		return err
	}
	suspicious += n

	if suspicious > 0 {
		rec.Message("%d dynamic linker injection point(s)", suspicious)
	} else {
		rec.Message("No preloaded libraries or unusual library directories")
	}
	return nil
}

// unparsed records a configuration file that could not be read completely.
func unparsed(rec *core.Recorder, path string, err error) {
	rec.Suspicious(core.Finding{
		Description: fmt.Sprintf("%s could not be parsed completely: %v", path, err),
		Details:     map[string]string{"path": path, "error": err.Error()},
		Why: "Dynamic linker configuration files are a few lines long. One padded past the size a parser " +
			"accepts stops scanners at that point, so entries after it go unseen.",
		Benign: "None expected; open the file and check what follows the padding.",
	})
}

// checkPreloadFile reports /etc/ld.so.preload. ld.so loads every library
// listed there into every dynamically linked program.
func (c *Cell) checkPreloadFile(rec *core.Recorder) int {
	const name = "/etc/ld.so.preload"
	data, err := fsutil.ReadSystemFile(c.path(name), fsutil.MaxConfig)
	if errors.Is(err, fs.ErrNotExist) {
		return 0
	}
	n := 0
	if errors.Is(err, fsutil.ErrTooLarge) {
		n++
		unparsed(rec, name, err)
	} else if err != nil {
		rec.Observe(fmt.Sprintf("%s was not read: %v", name, err), map[string]string{"path": name, "error": err.Error()})
		return 0
	}
	if hidden, err := c.hiddenFromListing(name); err != nil {
		rec.Limit("Could not check whether %s is hidden from its directory listing: %v", name, err)
	} else if hidden {
		n++
		rec.Suspicious(core.Finding{
			Description: name + " exists but is hidden from directory listings",
			Details:     map[string]string{"path": name},
			Why: "The file can be read by name, yet it is filtered out of /etc's listing. Userland rootkits hide their " +
				"preload configuration this way so that ls doesn't reveal it.",
			Benign: "None expected.",
		})
	}
	libs := ParsePreload(data)
	if len(libs) == 0 {
		return n
	}
	n++
	rec.Suspicious(core.Finding{
		Description: fmt.Sprintf("%s preloads %d librar%s into every program: %s", name, len(libs), plural(len(libs), "y", "ies"), strings.Join(libs, ", ")),
		Details:     map[string]string{"path": name, "libraries": strings.Join(libs, ", ")},
		Why: "The dynamic linker loads these libraries into every dynamically linked program before libc. Userland " +
			"rootkits use it to hook libc functions (readdir, open, stat...) and hide files, processes and connections " +
			"from ls, ps and netstat. Zygarde doesn't use libc, so its own views are unaffected.",
		Benign: "Rarely legitimate: some security or monitoring agents and memory allocators install a system-wide " +
			"preload. Check which package owns each library (dpkg -S, rpm -qf).",
	})
	for _, lib := range libs {
		n += c.checkLibrary(rec, lib, nil, name)
	}
	return n
}

// ParsePreload splits ld.so.preload content into library names: entries are
// separated by whitespace or ':', and '#' starts a comment (elf/rtld.c).
// Lines of any length are handled.
func ParsePreload(data []byte) []string {
	var libs []string
	for _, raw := range bytes.Split(data, []byte{'\n'}) {
		line, _, _ := strings.Cut(string(raw), "#")
		for _, f := range strings.FieldsFunc(line, func(r rune) bool { return r == ':' || r == ' ' || r == '\t' || r == '\r' }) {
			libs = append(libs, f)
		}
	}
	return libs
}

// checkLdSoConf reports library directories configured for the dynamic
// linker that are places attackers can write to or hide in.
func (c *Cell) checkLdSoConf(rec *core.Recorder) int {
	w := &confWalk{visited: map[string]bool{}}
	dirs := c.ldSoConfDirs("/etc/ld.so.conf", 0, w)
	n := 0
	for _, p := range w.unparsed {
		n++
		unparsed(rec, p.path, p.err)
	}
	if w.truncated {
		rec.Limit("ld.so.conf includes more than %d files; the rest were not read", maxConfFiles)
	}
	for _, d := range dirs {
		why := c.unusualDir(d.dir, "")
		if why == "" {
			continue
		}
		n++
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("The dynamic linker searches %s for libraries (%s), %s", d.dir, d.source, why),
			Details:     map[string]string{"directory": d.dir, "configured_in": d.source, "reason": why},
			Why: "ldconfig adds the libraries in this directory to the linker cache, so a library placed there can " +
				"shadow a system library (e.g. a trojaned libc or libpam) for every program.",
			Benign: "A local application installing libraries in an odd place. Check which package owns the " +
				"configuration file (dpkg -S, rpm -qf).",
		})
	}
	return n
}

type confDir struct {
	dir, source string
}

// maxConfFiles bounds how many ld.so.conf files are read, includes included.
const maxConfFiles = 512

// confWalk is the state of one ld.so.conf traversal.
type confWalk struct {
	visited   map[string]bool // files already read: include loops and repeats
	files     int
	truncated bool
	unparsed  []struct {
		path string
		err  error
	}
}

// ldSoConfDirs parses an ld.so.conf file and its includes (ldconfig(8)):
// directories separated by whitespace, ':' or ','; "include <glob>" lines;
// "hwcap" lines (ignored); '#' comments. Each file is read once.
func (c *Cell) ldSoConfDirs(file string, depth int, w *confWalk) []confDir {
	if depth > 8 || w.visited[file] {
		return nil
	}
	w.visited[file] = true
	if w.files++; w.files > maxConfFiles {
		w.truncated = true
		return nil
	}
	data, err := fsutil.ReadSystemFile(c.path(file), fsutil.MaxConfig)
	if errors.Is(err, fsutil.ErrTooLarge) {
		w.unparsed = append(w.unparsed, struct {
			path string
			err  error
		}{file, err})
	} else if err != nil {
		return nil
	}
	var out []confDir
	for i, raw := range bytes.Split(data, []byte{'\n'}) {
		line, _, _ := strings.Cut(string(raw), "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "include":
			for _, pattern := range fields[1:] {
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(filepath.Dir(file), pattern)
				}
				matches, _ := filepath.Glob(c.path(pattern))
				sort.Strings(matches)
				for _, m := range matches {
					out = append(out, c.ldSoConfDirs(strings.TrimPrefix(m, c.root), depth+1, w)...)
				}
			}
		case "hwcap":
		default:
			for _, d := range strings.FieldsFunc(line, func(r rune) bool { return r == ':' || r == ',' || r == ' ' || r == '\t' || r == '\r' }) {
				// "dir=TYPE" (libc5/libc6 hint) is still accepted by ldconfig.
				d, _, _ = strings.Cut(d, "=")
				out = append(out, confDir{d, fmt.Sprintf("%s:%d", file, i+1)})
			}
		}
	}
	return out
}

// unusualDir explains why a library directory is unusual, or returns "".
// root is the process's root directory (/proc/<pid>/root) when dir must be
// resolved in another mount namespace, or "" for the host.
func (c *Cell) unusualDir(dir, root string) string {
	if !filepath.IsAbs(dir) {
		return ""
	}
	dir = filepath.Clean(dir)
	switch {
	case under(dir, "/dev/shm"), under(dir, "/run/shm"):
		return "a memory-backed directory"
	case under(dir, "/tmp"), under(dir, "/var/tmp"):
		return "a temporary directory"
	case hiddenComponent(dir):
		return "a hidden directory"
	}
	var st unix.Stat_t
	if root == "" {
		if unix.Stat(c.path(dir), &st) != nil {
			return ""
		}
	} else {
		f, err := fsutil.OpenInRoot(root, dir, unix.O_PATH|unix.O_DIRECTORY)
		if err != nil {
			return ""
		}
		err = unix.Fstat(int(f.Fd()), &st)
		f.Close()
		if err != nil {
			return ""
		}
	}
	if st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Mode&0o002 != 0 {
		return "a world-writable directory"
	}
	return ""
}

// presence is what one lookup of a library found.
type presence int

const (
	unknown presence = iota // could not be determined in this root
	missing
	listed
	hidden // exists, but missing from its directory's listing
)

// lookup checks lib in one root: "" for the host (c.root), or a process's
// /proc/<pid>/root, resolved with openat2(RESOLVE_IN_ROOT) so the image's
// own absolute symlinks don't resolve against the host.
func (c *Cell) lookup(lib, root string) (presence, error) {
	if root == "" || fsutil.SameAsHostRoot(root) && c.root == "" {
		full := c.path(lib)
		if _, err := os.Lstat(full); errors.Is(err, fs.ErrNotExist) {
			return missing, nil
		} else if err != nil {
			return unknown, nil
		}
		found, err := fsutil.InListing(filepath.Dir(full), filepath.Base(full))
		if err != nil {
			return unknown, err
		}
		if found {
			return listed, nil
		}
		return hidden, nil
	}
	f, err := fsutil.OpenInRoot(root, lib, unix.O_PATH|unix.O_NOFOLLOW)
	if errors.Is(err, fs.ErrNotExist) {
		if _, serr := os.Stat(root); serr != nil {
			return unknown, nil // the process exited
		}
		return missing, nil
	}
	if err != nil {
		return unknown, err
	}
	f.Close()
	d, err := fsutil.OpenInRoot(root, filepath.Dir(lib), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NONBLOCK)
	if err != nil {
		return unknown, err
	}
	defer d.Close()
	found, err := fsutil.InListingFile(d, filepath.Base(lib))
	if err != nil {
		return unknown, err
	}
	if found {
		return listed, nil
	}
	return hidden, nil
}

// maxRoots bounds how many processes' roots a library is looked up in.
const maxRoots = 20

// checkLibrary reports a preloaded library that is missing, lives in an
// unusual directory or is hidden from its directory's listing. roots are the
// root directories (/proc/<pid>/root) of the processes that preload it, or
// nil for the host. A library only counts as missing or hidden if it is so
// in every root where it could be checked: processes in different mount
// namespaces, or a PID reused since, see different files.
func (c *Cell) checkLibrary(rec *core.Recorder, lib string, roots []string, source string) int {
	if !filepath.IsAbs(lib) || strings.Contains(lib, "$") {
		return 0 // searched in the library path, or a dynamic string token
	}
	if roots == nil {
		roots = []string{""}
	}
	if len(roots) > maxRoots {
		roots = roots[:maxRoots]
	}
	var why string
	if w := c.unusualDir(filepath.Dir(lib), roots[0]); w != "" {
		why = "it lives in " + w
	} else {
		counts := map[presence]int{}
		noOpenat2 := false
		for _, root := range roots {
			p, err := c.lookup(lib, root)
			if errors.Is(err, fsutil.ErrNoOpenat2) {
				noOpenat2 = true
			} else if err != nil {
				rec.Log().Debug("library lookup failed", "library", lib, "root", root, "err", err)
			}
			counts[p]++
		}
		if noOpenat2 {
			rec.Limit("Library %s not looked up inside other mount namespaces: %v", lib, fsutil.ErrNoOpenat2)
		}
		switch {
		case counts[listed] > 0:
		case counts[hidden] > 0:
			why = "it is hidden from directory listings"
		case counts[missing] > 0:
			why = "it is missing from disk"
		}
	}
	if why == "" {
		return 0
	}
	rec.Suspicious(core.Finding{
		Description: fmt.Sprintf("Preloaded library %s (%s): %s", lib, source, why),
		Details:     map[string]string{"library": lib, "preloaded_by": source, "reason": why},
		Why: "A preloaded library runs inside every affected program. One that was deleted after loading, sits in a " +
			"temporary, memory-backed or hidden directory, or is filtered out of listings is hiding where it came from.",
		Benign: "A library uninstalled while a long-running process that preloads it is still running.",
	})
	return 1
}

// injectionVars are environment variables that make ld.so load extra code.
var injectionVars = []string{"LD_PRELOAD", "LD_AUDIT"}

// checkEnvironments reports processes started with LD_PRELOAD, LD_AUDIT or
// an LD_LIBRARY_PATH pointing at an unusual directory.
func (c *Cell) checkEnvironments(ctx context.Context, rec *core.Recorder) (int, error) {
	entries, err := os.ReadDir(c.proc)
	if err != nil {
		return 0, fmt.Errorf("listing %s: %w", c.proc, err)
	}
	type use struct {
		variable, value string
	}
	pids := map[use][]string{}
	unreadable := 0
	for _, e := range entries {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(c.proc, pid, "environ"))
		if err != nil {
			// Kernel threads have no environment (an empty command line).
			cmdline, cerr := os.ReadFile(filepath.Join(c.proc, pid, "cmdline"))
			if !errors.Is(err, fs.ErrNotExist) && cerr == nil && len(cmdline) > 0 {
				unreadable++
			}
			continue
		}
		for k, v := range ParseEnviron(data) {
			isInjection := false
			for _, iv := range injectionVars {
				isInjection = isInjection || k == iv
			}
			if (isInjection && strings.TrimSpace(v) != "") || k == "LD_LIBRARY_PATH" {
				u := use{k, v}
				pids[u] = append(pids[u], pid)
			}
		}
	}
	if unreadable > 0 {
		rec.Limit("Environment of %d process(es) could not be read", unreadable)
	}

	keys := make([]use, 0, len(pids))
	for u := range pids {
		keys = append(keys, u)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].variable+keys[i].value < keys[j].variable+keys[j].value })

	n := 0
	for _, u := range keys {
		if ctx.Err() != nil {
			return n, ctx.Err()
		}
		list := pids[u]
		sort.Slice(list, func(i, j int) bool { a, _ := strconv.Atoi(list[i]); b, _ := strconv.Atoi(list[j]); return a < b })
		roots := make([]string, len(list))
		for i, pid := range list {
			roots[i] = filepath.Join(c.proc, pid, "root")
		}
		shown := list
		if len(shown) > 20 {
			shown = append(shown[:20:20], fmt.Sprintf("… (%d more)", len(list)-20))
		}
		details := map[string]string{"variable": u.variable, "value": u.value, "pids": strings.Join(shown, ", ")}
		source := fmt.Sprintf("%s of process %s", u.variable, list[0])

		if u.variable == "LD_LIBRARY_PATH" {
			var odd []string
			for _, d := range filepath.SplitList(u.value) {
				if why := c.unusualDir(d, roots[0]); why != "" {
					odd = append(odd, d+" ("+why+")")
				}
			}
			if len(odd) > 0 {
				details["unusual"] = strings.Join(odd, ", ")
				rec.Observe(fmt.Sprintf("%d process(es) search unusual library directories (LD_LIBRARY_PATH): %s", len(list), strings.Join(odd, ", ")), details)
			}
			continue
		}

		rec.Observe(fmt.Sprintf("%d process(es) run with %s=%s", len(list), u.variable, u.value), details)
		for _, lib := range strings.FieldsFunc(u.value, func(r rune) bool { return r == ':' || r == ' ' }) {
			n += c.checkLibrary(rec, lib, roots, source)
		}
	}
	return n, nil
}

// ParseEnviron parses /proc/<pid>/environ (NUL-separated KEY=value).
func ParseEnviron(data []byte) map[string]string {
	env := map[string]string{}
	for _, kv := range bytes.Split(data, []byte{0}) {
		if k, v, ok := strings.Cut(string(kv), "="); ok && k != "" {
			env[k] = v
		}
	}
	return env
}

func (c *Cell) path(p string) string { return filepath.Join(c.root, p) }

// hiddenFromListing reports whether a system path is missing from its
// directory's listing although it exists. The listing is streamed and stops
// at the first match.
func (c *Cell) hiddenFromListing(p string) (bool, error) {
	full := c.path(p)
	if _, err := os.Lstat(full); err != nil {
		return false, nil
	}
	found, err := fsutil.InListing(filepath.Dir(full), filepath.Base(full))
	return err == nil && !found, err
}

func under(p, dir string) bool { return p == dir || strings.HasPrefix(p, dir+"/") }

func hiddenComponent(p string) bool {
	for _, part := range strings.Split(p, "/") {
		if strings.HasPrefix(part, ".") && part != "." && part != ".." {
			return true
		}
	}
	return false
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
