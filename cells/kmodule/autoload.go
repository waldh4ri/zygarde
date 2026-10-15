package kmodule

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fsutil"
)

// Boot-time module configuration (modules-load.d(5), modprobe.d(5)), in the
// order systemd and kmod read them.
var (
	modulesLoadDirs = []string{"/etc/modules-load.d", "/run/modules-load.d", "/usr/local/lib/modules-load.d", "/usr/lib/modules-load.d", "/lib/modules-load.d"}
	modprobeDirs    = []string{"/etc/modprobe.d", "/run/modprobe.d", "/usr/local/lib/modprobe.d", "/usr/lib/modprobe.d", "/lib/modprobe.d"}
	// Scripts run at boot or login that may insmod/modprobe a module
	// directly (Mélofée uses /etc/rc.modules and rc.local).
	bootScripts = []string{"/etc/rc.modules", "/etc/rc.local", "/etc/rc.d/rc.local", "/etc/rc.d/rc.modules",
		"/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/root/.bashrc", "/root/.profile", "/root/.bash_profile"}
)

// configured is a module some boot configuration loads.
type configured struct {
	Module string // a module name, or a path for insmod
	Path   bool   // Module is a file path (insmod)
	Source string // file:line
	How    string // "modules-load.d", "/etc/modules", "insmod", "modprobe"
}

// install is a modprobe.d "install" directive: a command run instead of
// loading the module.
type install struct {
	Module, Command, Source string
}

// parseModuleList parses modules-load.d files and /etc/modules: one module
// per line, optionally followed by parameters; # and ; start comments.
func parseModuleList(r io.Reader, file, how string) ([]configured, error) {
	var out []configured
	sc := fsutil.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		out = append(out, configured{Module: strings.Fields(line)[0], Source: fmt.Sprintf("%s:%d", file, n), How: how})
	}
	return out, sc.Err()
}

// parseModprobeConf returns the install directives of a modprobe.d file.
// Lines ending in a backslash continue on the next line.
func parseModprobeConf(r io.Reader, file string) ([]install, error) {
	var out []install
	sc := fsutil.NewScanner(r)
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
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "install" {
			continue
		}
		cmd := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(line, "install")), f[1]))
		out = append(out, install{Module: f[1], Command: cmd, Source: fmt.Sprintf("%s:%d", file, start)})
	}
	return out, sc.Err()
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
func parseScript(r io.Reader, file string) ([]configured, error) {
	var out []configured
	sc := fsutil.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		for _, words := range commands(sc.Text()) {
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
			out = append(out, configured{Module: args[0], Path: prog == "insmod", Source: fmt.Sprintf("%s:%d", file, n), How: prog})
		}
	}
	return out, sc.Err()
}

// benignInstall reports whether an install command only runs programs used
// to disable a module or to load it with extra steps: true/false (the usual
// blacklisting idiom), modprobe itself, sysctl, logger, echo, and SUSE's
// unblacklist helper (suse-module-tools' 50-blacklist.conf).
func benignInstall(cmd string) bool {
	allowed := map[string]bool{"true": true, "false": true, ":": true, "modprobe": true, "sysctl": true,
		"logger": true, "echo": true, "exit": true}
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
			f, err := fsutil.OpenSystem(filepath.Join(root, dir, idx))
			if err != nil {
				continue
			}
			if idx == "modules.dep" {
				t.ok = true
			}
			sc := fsutil.NewScanner(f)
			for sc.Scan() {
				p, _, _ := strings.Cut(sc.Text(), ":")
				name := path.Base(strings.TrimSpace(p))
				if i := strings.Index(name, ".ko"); i > 0 {
					t.names[normalize(name[:i])] = true
				}
			}
			f.Close()
		}
		if f, err := fsutil.OpenSystem(filepath.Join(root, dir, "modules.alias")); err == nil {
			sc := fsutil.NewScanner(f)
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
		p := filepath.Clean(c.Module)
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

// confFiles lists the *.conf files of the given directories. As in systemd
// and kmod, a file overrides same-named files in later directories (which
// also skips /lib/... when it is a symlink to /usr/lib/...).
func confFiles(root string, dirs []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, d := range dirs {
		entries, err := os.ReadDir(filepath.Join(root, d))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".conf") && !e.IsDir() && !seen[e.Name()] {
				seen[e.Name()] = true
				out = append(out, filepath.Join(d, e.Name()))
			}
		}
	}
	return out
}

// hiddenFromListing reports whether path exists but is missing from its
// parent directory's listing: hidden by a getdents hook. The listing is
// streamed and stops at the first match; err is set if it could not be
// completed.
func hiddenFromListing(root, p string) (bool, error) {
	full := filepath.Join(root, p)
	if _, err := os.Lstat(full); err != nil {
		return false, nil
	}
	found, err := fsutil.InListing(filepath.Dir(full), filepath.Base(full))
	if err != nil {
		return false, err
	}
	return !found, nil
}

func under(p, dir string) bool { return p == dir || strings.HasPrefix(p, dir+"/") }

// homeOf returns the home directory (/home/<user>) a path is in.
func homeOf(p string) string {
	parts := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 3)
	if len(parts) < 2 {
		return p
	}
	return "/" + parts[0] + "/" + parts[1]
}

// ownedByHomeOwner reports whether f belongs to root or to the owner of the
// home directory it is in. A file placed by another user is not that
// user's login profile.
func ownedByHomeOwner(f *os.File, home string) bool {
	uid, err := fsutil.Owner(f)
	if err != nil {
		return false
	}
	if uid == 0 {
		return true
	}
	var st unix.Stat_t
	return unix.Stat(home, &st) == nil && st.Uid == uid
}

// checkAutoload reports modules configured to load at boot.
func (c *Cell) checkAutoload(rec *core.Recorder) int {
	var mods []configured
	var installs []install
	suspicious, userSkipped := 0, 0
	// read parses one file. Files under /home belong to their users: a
	// symlink there is never followed (it could point at a device), and a
	// file owned by someone other than root or the home's owner is skipped.
	// System files may be root-owned symlinks (/etc/rc.local -> rc.d/rc.local).
	read := func(p string, parse func(io.Reader) error) {
		full := filepath.Join(c.root, p)
		user := under(p, "/home")
		var f *os.File
		var err error
		if user {
			f, err = fsutil.Open(full)
		} else {
			f, err = fsutil.OpenSystem(full)
		}
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOTDIR) {
			return
		}
		if err != nil {
			if user {
				userSkipped++
			} else {
				rec.Observe(fmt.Sprintf("%s was not read: %v", p, err), map[string]string{"path": p, "error": err.Error()})
			}
			return
		}
		defer f.Close()
		if user && !ownedByHomeOwner(f, filepath.Join(c.root, homeOf(p))) {
			userSkipped++
			return
		}
		data, err := fsutil.ReadAll(f, fsutil.MaxConfig)
		if err == nil {
			err = parse(bytes.NewReader(data))
		}
		switch {
		case err == nil:
		case user:
			rec.Limit("%s was not parsed completely: %v", p, err)
		default:
			suspicious++
			rec.Suspicious(core.Finding{
				Description: fmt.Sprintf("%s could not be parsed completely: %v", p, err),
				Details:     map[string]string{"path": p, "error": err.Error()},
				Why: "Boot scripts and module configuration are small text files. One padded past the size or line " +
					"length a parser accepts stops scanners at that point, so whatever follows (an insmod line) goes unseen.",
				Benign: "A generated file or a script with an embedded payload. Open it and check what follows the long line.",
			})
		}
	}

	for _, p := range confFiles(c.root, modulesLoadDirs) {
		read(p, func(r io.Reader) error {
			m, err := parseModuleList(r, p, "modules-load.d")
			mods = append(mods, m...)
			return err
		})
	}
	read("/etc/modules", func(r io.Reader) error {
		m, err := parseModuleList(r, "/etc/modules", "/etc/modules")
		mods = append(mods, m...)
		return err
	})
	for _, p := range confFiles(c.root, modprobeDirs) {
		read(p, func(r io.Reader) error {
			in, err := parseModprobeConf(r, p)
			installs = append(installs, in...)
			return err
		})
	}
	read("/etc/modprobe.conf", func(r io.Reader) error {
		in, err := parseModprobeConf(r, "/etc/modprobe.conf")
		installs = append(installs, in...)
		return err
	})

	scripts := append([]string{}, bootScripts...)
	if matches, err := filepath.Glob(filepath.Join(c.root, "/etc/profile.d/*.sh")); err == nil {
		for _, m := range matches {
			scripts = append(scripts, strings.TrimPrefix(m, c.root))
		}
	}
	if homes, err := os.ReadDir(filepath.Join(c.root, "/home")); err == nil {
		for _, h := range homes {
			for _, f := range []string{".bashrc", ".profile", ".bash_profile"} {
				scripts = append(scripts, path.Join("/home", h.Name(), f))
			}
		}
	}
	for _, p := range scripts {
		read(p, func(r io.Reader) error {
			m, err := parseScript(r, p)
			mods = append(mods, m...)
			return err
		})
	}
	if userSkipped > 0 {
		rec.Limit("%d shell profile(s) under /home not read: symlinks, non-regular files, or files owned by neither root nor the home's owner", userSkipped)
	}

	tree := loadModuleTree(c.root, c.release)
	for _, m := range mods {
		details := map[string]string{"module": m.Module, "configured_in": m.Source, "loaded_by": m.How}
		if !m.Path {
			// modprobe only looks in the running kernel's module tree, so a
			// name that isn't there can't load: a stale or foreign entry,
			// not a way to persist (a rootkit's own module would be found).
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
		details := map[string]string{"module": in.Module, "command": in.Command, "configured_in": in.Source}
		if benignInstall(in.Command) {
			rec.Observe(fmt.Sprintf("modprobe runs a command instead of loading %s (%s)", in.Module, in.Source), details)
			continue
		}
		suspicious++
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("modprobe.d runs a command whenever %s is loaded: %s", in.Module, in.Command),
			Details:     details,
			Why: "An install directive replaces loading the module with an arbitrary command run as root. Attackers use " +
				"it to execute code (or insmod their own module) whenever a common module gets loaded.",
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
		hidden, err := hiddenFromListing(c.root, p)
		if err != nil {
			rec.Limit("Could not check whether %s is hidden from its directory listing: %v", p, err)
			continue
		}
		if hidden {
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
