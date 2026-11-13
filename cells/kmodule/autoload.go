package kmodule

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fsutil"
)

// Boot-time module configuration (modules-load.d(5), modprobe.d(5), systemd
// units and udev rules), in the order systemd and kmod read them.
var (
	modulesLoadDirs = []string{"/etc/modules-load.d", "/run/modules-load.d", "/usr/local/lib/modules-load.d", "/usr/lib/modules-load.d", "/lib/modules-load.d"}
	modprobeDirs    = []string{"/etc/modprobe.d", "/run/modprobe.d", "/usr/local/lib/modprobe.d", "/usr/lib/modprobe.d", "/lib/modprobe.d"}
	// Scripts run at boot or login that may insmod/modprobe a module
	// directly (Mélofée uses /etc/rc.modules and rc.local).
	bootScripts = []string{"/etc/rc.modules", "/etc/rc.local", "/etc/rc.d/rc.local", "/etc/rc.d/rc.modules",
		"/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/root/.bashrc", "/root/.profile", "/root/.bash_profile"}
)

var udevRunRe = regexp.MustCompile(`RUN(?:\+|\:)?="([^"]+)"`)

// configured is a module some boot configuration loads.
type configured struct {
	Module string // a module name, or a path for insmod
	Path   bool   // Module is a file path (insmod)
	Source string // file:line
	How    string // "modules-load.d", "/etc/modules", "insmod", "modprobe"
}

// install is a modprobe.d "install" or "remove" directive: a command run
// instead of loading or unloading the module.
type install struct {
	Directive string // "install" or "remove"
	Module    string
	Command   string
	Source    string
}

// parseModuleList parses modules-load.d files and /etc/modules: one module
// per line, optionally followed by parameters; # and ; start comments.
func parseModuleList(r io.Reader, file, how string) []configured {
	var out []configured
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		out = append(out, configured{Module: strings.Fields(line)[0], Source: fmt.Sprintf("%s:%d", file, n), How: how})
	}
	return out
}

// parseModprobeConf returns the install and remove directives of a modprobe.d
// file. Lines ending in a backslash continue on the next line.
func parseModprobeConf(r io.Reader, file string) []install {
	var out []install
	sc := bufio.NewScanner(r)
	var cont strings.Builder
	start := 0
	for n := 1; sc.Scan(); n++ {
		text := sc.Text()
		if cont.Len() == 0 {
			start = n
		}
		if strings.HasSuffix(text, "\\") {
			cont.WriteString(strings.TrimSuffix(text, "\\") + " ")
			continue
		}
		cont.WriteString(text)
		line := strings.TrimSpace(cont.String())
		cont.Reset()
		if strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 || (f[0] != "install" && f[0] != "remove") {
			continue
		}
		cmd := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(line, f[0])), f[1]))
		out = append(out, install{Directive: f[0], Module: f[1], Command: cmd, Source: fmt.Sprintf("%s:%d", file, start)})
	}
	return out
}

// commands splits a shell line into simple commands (on ; && || | and
// newlines) and returns each one's words, without comments.
func commands(line string) [][]string {
	if i := strings.Index(line, "#"); i >= 0 && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
		line = line[:i]
	}
	r := strings.NewReplacer("&&", ";", "||", ";", "|", ";", "&", ";")
	var out [][]string
	for _, part := range strings.Split(r.Replace(line), ";") {
		words := strings.Fields(part)
		// Skip grouping, env assignments and wrappers to reach the program.
		for len(words) > 0 {
			w := words[0]
			if w == "{" || w == "(" || w == "}" || w == ")" || w == "then" || w == "do" || w == "else" ||
				w == "exec" || w == "sudo" || w == "nohup" || (strings.Contains(w, "=") && !strings.HasPrefix(w, "=")) {
				words = words[1:]
				continue
			}
			break
		}
		if len(words) > 0 {
			out = append(out, words)
		}
	}
	return out
}

// parseScript finds insmod and modprobe commands in a shell script.
func parseScript(r io.Reader, file string) []configured {
	var out []configured
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		out = append(out, extractModCmds(sc.Text(), file, n)...)
	}
	return out
}

func extractModCmds(text, file string, lineNo int) []configured {
	var out []configured
	for _, words := range commands(text) {
		prog := path.Base(strings.Trim(words[0], `"'`))
		if prog != "insmod" && prog != "modprobe" {
			continue
		}
		var args []string
		remove := false
		for _, a := range words[1:] {
			switch {
			case a == "-r" || a == "--remove":
				remove = true
			case strings.HasPrefix(a, "-"):
			default:
				args = append(args, strings.Trim(a, `"'`))
			}
		}
		if remove || len(args) == 0 || strings.HasPrefix(args[0], "$") {
			continue
		}
		out = append(out, configured{Module: args[0], Path: prog == "insmod", Source: fmt.Sprintf("%s:%d", file, lineNo), How: prog})
	}
	return out
}

// parseSystemdUnit finds ExecStart/ExecStartPre/ExecStartPost lines loading modules.
func parseSystemdUnit(r io.Reader, file string) []configured {
	var out []configured
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || !strings.HasPrefix(strings.TrimSpace(k), "Exec") {
			continue
		}
		v = strings.TrimLeft(strings.TrimSpace(v), "-+@!:")
		out = append(out, extractModCmds(v, file, n)...)
	}
	return out
}

// parseUdevRules finds RUN+="..." actions that invoke insmod or modprobe.
func parseUdevRules(r io.Reader, file string) []configured {
	var out []configured
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		for _, m := range udevRunRe.FindAllStringSubmatch(line, -1) {
			out = append(out, extractModCmds(m[1], file, n)...)
		}
	}
	return out
}

// benignInstall reports whether an install/remove command only runs programs
// used to disable a module or to load it with extra steps: true/false (the
// usual blacklisting idiom), modprobe itself, sysctl, logger, echo, and SUSE's
// unblacklist helper, without shell command substitution or redirection.
func benignInstall(cmd string) bool {
	// Command substitution or redirection inside arguments (e.g.
	// `/bin/true $(insmod /etc/rk.ko)` or ``/bin/echo `...` ``) executes
	// arbitrary commands even when argv[0] is on the allowlist.
	for _, sub := range []string{"$(", "`", "<(", ">(", "\n", "\r"} {
		if strings.Contains(cmd, sub) {
			return false
		}
	}
	allowed := map[string]bool{"true": true, "false": true, ":": true, "modprobe": true, "rmmod": true,
		"lsmod": true, "grep": true, "xargs": true, "sysctl": true, "logger": true, "echo": true, "exit": true}
	helpers := map[string]bool{"/usr/lib/module-init-tools/unblacklist": true, "/lib/module-init-tools/unblacklist": true}
	cmds := commands(cmd)
	if len(cmds) == 0 {
		return false
	}
	for _, words := range cmds {
		prog := words[0]
		if helpers[prog] {
			continue
		}
		if !allowed[path.Base(prog)] {
			return false
		}
		if strings.HasPrefix(prog, "/") {
			switch path.Dir(prog) {
			case "/bin", "/sbin", "/usr/bin", "/usr/sbin":
			default:
				return false
			}
		}
		// Reject modprobe loading an explicit file path via insmod-like wrappers.
		for _, w := range words[1:] {
			if strings.Contains(w, ">") && w != ">/dev/null" && w != "2>/dev/null" && w != "&>/dev/null" {
				return false
			}
		}
	}
	return true
}

// moduleTree indexes the modules shipped with the running kernel.
type moduleTree struct {
	dirs  []string            // /lib/modules/<release> and /usr/lib/modules/<release>
	names map[string]bool     // normalised names, loadable and built-in
	alias map[string][]string // alias pattern -> module
	ok    bool                // modules.dep was found
}

func normalize(name string) string { return strings.ReplaceAll(name, "-", "_") }

// loadModuleTree reads modules.dep, modules.builtin and modules.alias.
func loadModuleTree(root, release string) moduleTree {
	t := moduleTree{names: map[string]bool{}, alias: map[string][]string{}}
	for _, base := range []string{"/lib/modules/", "/usr/lib/modules/"} {
		t.dirs = append(t.dirs, base+release)
	}
	for _, dir := range t.dirs {
		for _, idx := range []string{"modules.dep", "modules.builtin"} {
			f, err := fsutil.OpenNoAtime(filepath.Join(root, dir, idx))
			if err != nil {
				continue
			}
			if idx == "modules.dep" {
				t.ok = true
			}
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				p, _, _ := strings.Cut(sc.Text(), ":")
				name := path.Base(strings.TrimSpace(p))
				if i := strings.Index(name, ".ko"); i > 0 {
					t.names[normalize(name[:i])] = true
				}
			}
			f.Close()
		}
		if f, err := fsutil.OpenNoAtime(filepath.Join(root, dir, "modules.alias")); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				if f := strings.Fields(sc.Text()); len(f) == 3 && f[0] == "alias" {
					t.alias[f[1]] = append(t.alias[f[1]], f[2])
				}
			}
			f.Close()
		}
	}
	return t
}

// shipped reports whether a configured module comes with the running kernel.
func (t moduleTree) shipped(c configured) bool {
	if c.Path {
		p := path.Clean(filepath.ToSlash(c.Module))
		for _, d := range t.dirs {
			if strings.HasPrefix(p, d+"/") {
				return true
			}
		}
		return false
	}
	if t.names[normalize(c.Module)] {
		return true
	}
	for pattern := range t.alias {
		if ok, _ := path.Match(pattern, c.Module); ok {
			return true
		}
	}
	return false
}

// confFiles lists the files with suffix of the given directories. As in systemd
// and kmod, a file overrides same-named files in later directories (which
// also skips /lib/... when it is a symlink to /usr/lib/...).
func confFiles(root string, dirs []string, suffix string) []string {
	var out []string
	seen := map[string]bool{}
	for _, d := range dirs {
		entries, err := fsutil.ReadDirNoAtime(filepath.Join(root, d))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), suffix) && !e.IsDir() && !seen[e.Name()] {
				seen[e.Name()] = true
				out = append(out, path.Join(d, e.Name()))
			}
		}
	}
	return out
}

// hiddenFromListing reports whether path exists but is missing from its
// parent directory's listing: hidden by a getdents hook.
func hiddenFromListing(root, p string) bool {
	full := filepath.Join(root, p)
	if _, err := os.Lstat(full); err != nil {
		return false
	}
	entries, err := fsutil.ReadDirNoAtime(filepath.Dir(full))
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Name() == filepath.Base(full) {
			return false
		}
	}
	return true
}

func relSlash(root, match string) string {
	if root == "" {
		return filepath.ToSlash(match)
	}
	if r, err := filepath.Rel(root, match); err == nil {
		return "/" + strings.TrimPrefix(filepath.ToSlash(r), "/")
	}
	return filepath.ToSlash(strings.TrimPrefix(match, root))
}

// checkAutoload reports modules configured to load at boot.
func (c *Cell) checkAutoload(rec *core.Recorder) int {
	var mods []configured
	var installs []install
	read := func(p string, parse func(io.Reader)) {
		f, err := fsutil.OpenNoAtime(filepath.Join(c.root, p))
		if err != nil {
			return
		}
		defer f.Close()
		parse(f)
	}

	for _, p := range confFiles(c.root, modulesLoadDirs, ".conf") {
		read(p, func(r io.Reader) { mods = append(mods, parseModuleList(r, p, "modules-load.d")...) })
	}
	read("/etc/modules", func(r io.Reader) { mods = append(mods, parseModuleList(r, "/etc/modules", "/etc/modules")...) })
	for _, p := range confFiles(c.root, modprobeDirs, ".conf") {
		read(p, func(r io.Reader) { installs = append(installs, parseModprobeConf(r, p)...) })
	}
	read("/etc/modprobe.conf", func(r io.Reader) { installs = append(installs, parseModprobeConf(r, "/etc/modprobe.conf")...) })

	scripts := append([]string{}, bootScripts...)
	if matches, err := filepath.Glob(filepath.Join(c.root, "etc/profile.d/*.sh")); err == nil {
		for _, m := range matches {
			scripts = append(scripts, relSlash(c.root, m))
		}
	}
	if homes, err := fsutil.ReadDirNoAtime(filepath.Join(c.root, "home")); err == nil {
		for _, h := range homes {
			for _, f := range []string{".bashrc", ".profile", ".bash_profile"} {
				scripts = append(scripts, path.Join("/home", h.Name(), f))
			}
		}
	}
	for _, p := range scripts {
		read(p, func(r io.Reader) { mods = append(mods, parseScript(r, p)...) })
	}
	for _, p := range confFiles(c.root, []string{"/etc/systemd/system", "/run/systemd/system"}, ".service") {
		read(p, func(r io.Reader) { mods = append(mods, parseSystemdUnit(r, p)...) })
	}
	for _, p := range confFiles(c.root, []string{"/etc/udev/rules.d", "/run/udev/rules.d"}, ".rules") {
		read(p, func(r io.Reader) { mods = append(mods, parseUdevRules(r, p)...) })
	}

	suspicious := 0
	tree := loadModuleTree(c.root, c.release)
	for _, m := range mods {
		details := map[string]string{"module": m.Module, "configured_in": m.Source, "loaded_by": m.How}
		if !m.Path {
			desc := fmt.Sprintf("Module %s is configured to load at boot (%s)", m.Module, m.Source)
			if tree.ok && !tree.shipped(m) {
				desc += " but this kernel has no such module"
			}
			rec.Observe(desc, details)
			continue
		}
		if tree.shipped(m) {
			rec.Observe(fmt.Sprintf("Module %s is configured to load at boot (%s)", m.Module, m.Source), details)
			continue
		}
		fsutil.MergeMetadata(details, "file_", fsutil.FileMetadata(filepath.Join(c.root, m.Module)))
		suspicious++
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("Module %s is loaded at boot (%s) from outside the running kernel's module tree", m.Module, m.Source),
			Details:     details,
			Why: "The module is loaded from a file outside /lib/modules/" + c.release + ". Kernel and DKMS modules " +
				"live there; rootkits keep theirs elsewhere (Mélofée: /etc/intel_audio/intel_audio.ko from /etc/rc.modules).",
			Benign: "A vendor driver installed by hand outside the module tree. Check where the file came from " +
				"and which package owns the script loading it (dpkg -S, rpm -qf).",
		})
	}

	for _, in := range installs {
		details := map[string]string{
			"directive":     in.Directive,
			"module":        in.Module,
			"command":       in.Command,
			"configured_in": in.Source,
		}
		action := "loaded"
		if in.Directive == "remove" {
			action = "unloaded"
		}
		if benignInstall(in.Command) {
			rec.Observe(fmt.Sprintf("modprobe runs a command when %s is %s (%s)", in.Module, action, in.Source), details)
			continue
		}
		suspicious++
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("modprobe.d runs a command whenever %s is %s: %s", in.Module, action, in.Command),
			Details:     details,
			Why: "An install or remove directive replaces module operations with an arbitrary command run as root. " +
				"Attackers use it to execute code (or insmod their own module) whenever a common module is touched.",
			Benign: "Distribution or vendor packages occasionally wrap module loading with scripts. Check which " +
				"package owns the file (dpkg -S, rpm -qf).",
		})
	}

	// Configuration files hidden from directory listings.
	fixed := append([]string{"/etc/modules", "/etc/modprobe.conf"}, bootScripts...)
	fixed = append(fixed, modulesLoadDirs...)
	fixed = append(fixed, modprobeDirs...)
	sort.Strings(fixed)
	for _, p := range fixed {
		if hiddenFromListing(c.root, p) {
			suspicious++
			rec.Suspicious(core.Finding{
				Description: fmt.Sprintf("%s exists but is hidden from directory listings", p),
				Details:     map[string]string{"path": p},
				Why: "This file or directory controls what loads at boot. It can be opened by name but is filtered " +
					"out of its directory's listing, so whatever it loads is being hidden on purpose.",
				Benign: "None expected.",
			})
		}
	}
	rec.Log().Debug("boot module configuration", "modules", len(mods), "installs", len(installs), "suspicious", suspicious)
	return suspicious
}
