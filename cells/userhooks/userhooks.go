// Package userhooks detects libraries injected into processes through the
// dynamic linker: /etc/ld.so.preload, unusual library directories and
// LD_PRELOAD.
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

// checkPreloadFile reports /etc/ld.so.preload. ld.so loads every library
// listed there into every dynamically linked program.
func (c *Cell) checkPreloadFile(rec *core.Recorder) int {
	const name = "/etc/ld.so.preload"
	data, err := os.ReadFile(c.path(name))
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
		n += c.checkLibrary(rec, lib, "", name)
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

// ldSoConfDirs parses an ld.so.conf file and its includes (ldconfig(8)):
// directories separated by whitespace, ':' or ','; "include <glob>" lines;
// "hwcap" lines (ignored); '#' comments.
func (c *Cell) ldSoConfDirs(file string, depth int) []confDir {
	if depth > 8 {
		return nil
	}
	f, err := os.Open(c.path(file))
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
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(filepath.Dir(file), pattern)
				}
				matches, _ := filepath.Glob(c.path(pattern))
				sort.Strings(matches)
				for _, m := range matches {
					out = append(out, c.ldSoConfDirs(strings.TrimPrefix(m, c.root), depth+1)...)
				}
			}
		case "hwcap":
		default:
			for _, d := range strings.FieldsFunc(line, func(r rune) bool { return r == ':' || r == ',' || r == ' ' || r == '\t' }) {
				// "dir=TYPE" (libc5/libc6 hint) is still accepted by ldconfig.
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
	full := c.path(dir)
	if root != "" {
		full = filepath.Join(root, dir)
	}
	if st, err := os.Stat(full); err == nil && st.IsDir() && st.Mode().Perm()&0o002 != 0 {
		return "a world-writable directory"
	}
	return ""
}

// checkLibrary reports a preloaded library that is missing, lives in an
// unusual directory or is hidden from its directory's listing. root is the
// process's root directory (/proc/<pid>/root) or "" for the host.
func (c *Cell) checkLibrary(rec *core.Recorder, lib, root, source string) int {
	if !filepath.IsAbs(lib) || strings.Contains(lib, "$") {
		return 0 // searched in the library path, or a dynamic string token
	}
	full := c.path(lib)
	if root != "" {
		if _, err := os.Stat(root); err != nil {
			return 0 // the process exited
		}
		full = filepath.Join(root, lib)
	}
	var why string
	if w := c.unusualDir(filepath.Dir(lib), root); w != "" {
		why = "it lives in " + w
	} else if _, err := os.Lstat(full); errors.Is(err, fs.ErrNotExist) {
		why = "it is missing from disk"
	} else if err == nil && hiddenFromListing(full) {
		why = "it is hidden from directory listings"
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
	roots := map[use]string{}
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
				if _, ok := roots[u]; !ok {
					roots[u] = filepath.Join(c.proc, pid, "root")
				}
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
		list := pids[u]
		sort.Slice(list, func(i, j int) bool { a, _ := strconv.Atoi(list[i]); b, _ := strconv.Atoi(list[j]); return a < b })
		shown := list
		if len(shown) > 20 {
			shown = append(shown[:20:20], fmt.Sprintf("… (%d more)", len(list)-20))
		}
		details := map[string]string{"variable": u.variable, "value": u.value, "pids": strings.Join(shown, ", ")}
		source := fmt.Sprintf("%s of process %s", u.variable, list[0])

		if u.variable == "LD_LIBRARY_PATH" {
			var odd []string
			for _, d := range filepath.SplitList(u.value) {
				if why := c.unusualDir(d, roots[u]); why != "" {
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
	entries, err := os.ReadDir(filepath.Dir(full))
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
