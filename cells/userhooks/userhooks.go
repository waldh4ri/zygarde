// Package userhooks detects libraries injected into processes through the
// dynamic linker: /etc/ld.so.preload, unusual library directories in
// ld.so.conf or /etc/ld.so.cache, LD_PRELOAD/LD_AUDIT in environments, and
// executable shared objects mapped from unusual paths in /proc/<pid>/maps.
package userhooks

import (
	"bufio"
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

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fsutil"
)

// Cell looks for userland rootkits that hook libc through the dynamic linker
// or inject shared libraries into running processes.
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
	return "Checks dynamic linker injection points (/etc/ld.so.preload, ld.so.conf, ld.so.cache, LD_PRELOAD) and suspicious mapped libraries in process memory"
}

func (c *Cell) Run(ctx context.Context, env *core.Env, rec *core.Recorder) error {
	suspicious := 0
	suspicious += c.checkPreloadFile(rec)
	suspicious += c.checkLdSoConf(rec)
	suspicious += c.checkLdSoCache(rec)
	n, err := c.checkEnvironments(ctx, rec)
	if err != nil {
		return err
	}
	suspicious += n
	m, err := c.checkProcessMaps(ctx, rec)
	if err != nil {
		return err
	}
	suspicious += m

	if suspicious > 0 {
		rec.Message("%d dynamic linker or memory injection point(s)", suspicious)
	} else {
		rec.Message("No preloaded libraries, unusual library directories or injected libraries")
	}
	return nil
}

// checkPreloadFile reports /etc/ld.so.preload. ld.so loads every library
// listed there into every dynamically linked program.
func (c *Cell) checkPreloadFile(rec *core.Recorder) int {
	const name = "/etc/ld.so.preload"
	data, err := fsutil.ReadFileNoAtime(c.path(name))
	if err != nil {
		return 0
	}
	n := 0
	if c.hiddenFromListing(name) {
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
	details := map[string]string{"path": name, "libraries": strings.Join(libs, ", ")}
	fsutil.MergeMetadata(details, "preload_file_", fsutil.FileMetadata(c.path(name)))
	rec.Suspicious(core.Finding{
		Description: fmt.Sprintf("%s preloads %d librar%s into every program: %s", name, len(libs), plural(len(libs), "y", "ies"), strings.Join(libs, ", ")),
		Details:     details,
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
func ParsePreload(data []byte) []string {
	var libs []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		for _, f := range strings.FieldsFunc(line, func(r rune) bool { return r == ':' || r == ' ' || r == '\t' }) {
			libs = append(libs, f)
		}
	}
	return libs
}

// checkLdSoConf reports library directories configured for the dynamic
// linker that are places attackers can write to or hide in.
func (c *Cell) checkLdSoConf(rec *core.Recorder) int {
	dirs := c.ldSoConfDirs("/etc/ld.so.conf", 0)
	n := 0
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

// ldSoConfDirs parses an ld.so.conf file and its includes (ldconfig(8)).
func (c *Cell) ldSoConfDirs(file string, depth int) []confDir {
	if depth > 8 {
		return nil
	}
	f, err := fsutil.OpenNoAtime(c.path(file))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []confDir
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "include":
			for _, pattern := range fields[1:] {
				if !strings.HasPrefix(pattern, "/") && !filepath.IsAbs(pattern) {
					pattern = filepath.ToSlash(filepath.Join(filepath.Dir(file), pattern))
				}
				matches, _ := filepath.Glob(c.path(pattern))
				sort.Strings(matches)
				for _, m := range matches {
					rel := m
					if c.root != "" {
						if r, err := filepath.Rel(c.root, m); err == nil {
							rel = "/" + strings.TrimPrefix(filepath.ToSlash(r), "/")
						}
					}
					out = append(out, c.ldSoConfDirs(rel, depth+1)...)
				}
			}
		case "hwcap":
		default:
			for _, d := range strings.FieldsFunc(line, func(r rune) bool { return r == ':' || r == ',' || r == ' ' || r == '\t' }) {
				d, _, _ = strings.Cut(d, "=")
				out = append(out, confDir{d, fmt.Sprintf("%s:%d", file, n)})
			}
		}
	}
	return out
}

// unusualDir explains why a library directory is unusual, or returns "".
// root prefixes the path when it must be resolved in another mount
// namespace (/proc/<pid>/root).
func (c *Cell) unusualDir(dir, root string) string {
	slash := filepath.ToSlash(dir)
	if !strings.HasPrefix(slash, "/") {
		return ""
	}
	slash = filepath.ToSlash(filepath.Clean(slash))
	if !strings.HasPrefix(slash, "/") {
		slash = "/" + slash
	}
	switch {
	case under(slash, "/dev/shm"), under(slash, "/run/shm"):
		return "a memory-backed directory"
	case under(slash, "/tmp"), under(slash, "/var/tmp"):
		return "a temporary directory"
	case hiddenComponent(slash):
		return "a hidden directory"
	}
	full := c.path(slash)
	if root != "" {
		full = filepath.Join(root, slash)
	}
	if st, err := os.Stat(full); err == nil && st.IsDir() && st.Mode().Perm()&0o002 != 0 {
		return "a world-writable directory"
	}
	return ""
}

// resolveLiveRoot picks the first /proc/<pid>/root from candidateRoots that
// still exists on disk, so a single short-lived process exiting mid-scan does
// not skip inspection for other processes in the same mount namespace.
func resolveLiveRoot(candidateRoots []string) (string, bool) {
	if len(candidateRoots) == 0 {
		return "", true
	}
	for _, r := range candidateRoots {
		if _, err := os.Stat(r); err == nil {
			return r, true
		}
	}
	return "", false
}

// checkLibrary reports a preloaded library that is missing, lives in an
// unusual directory or is hidden from its directory's listing.
func (c *Cell) checkLibrary(rec *core.Recorder, lib string, candidateRoots []string, source string) int {
	slash := filepath.ToSlash(lib)
	if !strings.HasPrefix(slash, "/") || strings.Contains(slash, "$") {
		return 0 // searched in the library path, or a dynamic string token
	}
	root, ok := resolveLiveRoot(candidateRoots)
	if !ok {
		return 0 // every candidate process in this namespace exited
	}
	full := c.path(slash)
	if root != "" {
		full = filepath.Join(root, slash)
	}
	var why string
	if w := c.unusualDir(filepath.ToSlash(filepath.Dir(slash)), root); w != "" {
		why = "it lives in " + w
	} else if _, err := os.Lstat(full); errors.Is(err, fs.ErrNotExist) {
		why = "it is missing from disk"
	} else if err == nil && hiddenFromListing(full) {
		why = "it is hidden from directory listings"
	}
	if why == "" {
		return 0
	}
	details := map[string]string{"library": lib, "preloaded_by": source, "reason": why}
	fsutil.MergeMetadata(details, "file_", fsutil.FileMetadata(full))
	rec.Suspicious(core.Finding{
		Description: fmt.Sprintf("Preloaded library %s (%s): %s", lib, source, why),
		Details:     details,
		Why: "A preloaded library runs inside every affected program. One that was deleted after loading, sits in a " +
			"temporary, memory-backed or hidden directory, or is filtered out of listings is hiding where it came from.",
		Benign: "A library uninstalled while a long-running process that preloads it is still running.",
	})
	return 1
}

// injectionVars are environment variables that make ld.so load extra code.
var injectionVars = []string{"LD_PRELOAD", "LD_AUDIT"}

// checkEnvironments reports processes started with LD_PRELOAD, LD_AUDIT or
// an LD_LIBRARY_PATH pointing at an unusual directory, grouping by mount
// namespace so container filesystems never shadow host processes.
func (c *Cell) checkEnvironments(ctx context.Context, rec *core.Recorder) (int, error) {
	entries, err := fsutil.ReadDirNoAtime(c.proc)
	if err != nil {
		return 0, fmt.Errorf("listing %s: %w", c.proc, err)
	}
	type use struct {
		mntNS, variable, value string
	}
	pids := map[use][]string{}
	roots := map[use][]string{}
	unreadable := 0
	for _, e := range entries {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		data, err := fsutil.ReadFileNoAtime(filepath.Join(c.proc, pid, "environ"))
		if err != nil {
			cmdline, cerr := fsutil.ReadFileNoAtime(filepath.Join(c.proc, pid, "cmdline"))
			if !errors.Is(err, fs.ErrNotExist) && cerr == nil && len(cmdline) > 0 {
				unreadable++
			}
			continue
		}
		mntNS, _ := os.Readlink(filepath.Join(c.proc, pid, "ns", "mnt"))
		procRoot := filepath.Join(c.proc, pid, "root")
		for k, v := range ParseEnviron(data) {
			isInjection := false
			for _, iv := range injectionVars {
				isInjection = isInjection || k == iv
			}
			if (isInjection && strings.TrimSpace(v) != "") || k == "LD_LIBRARY_PATH" {
				u := use{mntNS, k, v}
				pids[u] = append(pids[u], pid)
				roots[u] = append(roots[u], procRoot)
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
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].variable+keys[i].value+keys[i].mntNS < keys[j].variable+keys[j].value+keys[j].mntNS
	})

	n := 0
	for _, u := range keys {
		list := pids[u]
		sort.Slice(list, func(i, j int) bool { a, _ := strconv.Atoi(list[i]); b, _ := strconv.Atoi(list[j]); return a < b })
		shown := list
		if len(shown) > 20 {
			shown = append(shown[:20:20], fmt.Sprintf("… (%d more)", len(list)-20))
		}
		details := map[string]string{"variable": u.variable, "value": u.value, "pids": strings.Join(shown, ", ")}
		if u.mntNS != "" {
			details["mount_ns"] = u.mntNS
		}
		source := fmt.Sprintf("%s of process %s", u.variable, list[0])

		if u.variable == "LD_LIBRARY_PATH" {
			liveRoot, _ := resolveLiveRoot(roots[u])
			var odd []string
			for _, d := range strings.Split(u.value, ":") {
				if why := c.unusualDir(d, liveRoot); why != "" {
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
			n += c.checkLibrary(rec, lib, roots[u], source)
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
// directory's listing although it exists.
func (c *Cell) hiddenFromListing(p string) bool { return hiddenFromListing(c.path(p)) }

func hiddenFromListing(full string) bool {
	if _, err := os.Lstat(full); err != nil {
		return false
	}
	entries, err := fsutil.ReadDirNoAtime(filepath.Dir(full))
	if err != nil {
		return false
	}
	base := filepath.Base(full)
	for _, e := range entries {
		if e.Name() == base {
			return false
		}
	}
	return true
}

func under(p, dir string) bool { return p == dir || strings.HasPrefix(p, dir+"/") }

func hiddenComponent(p string) bool {
	for _, part := range strings.Split(filepath.ToSlash(p), "/") {
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
