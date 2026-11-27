// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

// Package umhelper audits the programs the kernel itself runs as root, its
// usermode helpers: modprobe (module autoloading), the core dump pipe
// (core_pattern), the hotplug helper (uevent_helper), the orderly poweroff
// command and cgroup v1 release agents.
package umhelper

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fsutil"
	"github.com/waldh4ri/zygarde/internal/kmem"
	"github.com/waldh4ri/zygarde/internal/pkgdb"
)

// strLen is how much of linux_banner, the canary, is read.
const strLen = 256

// helper is a kernel setting naming a program the kernel runs as root.
type helper struct {
	name    string // as shown in findings
	symbol  string // the kernel variable holding it
	file    string // where userspace reads it
	size    uint32 // size of the kernel variable
	trigger string // what makes the kernel run it
}

var helpers = []helper{
	{"modprobe", "modprobe_path", "/proc/sys/kernel/modprobe", 256,
		"whenever something requests a module that is not loaded (an unknown socket family, filesystem or binary format), which any user can cause"},
	{"core_pattern", "core_pattern", "/proc/sys/kernel/core_pattern", 128,
		"when it starts with |, for every process that dumps core, which any user can cause"},
	{"uevent_helper", "uevent_helper", "/sys/kernel/uevent_helper", 256,
		"for every device event (hotplug)"},
	{"poweroff_cmd", "poweroff_cmd", "/proc/sys/kernel/poweroff_cmd", 256,
		"on an orderly poweroff requested by the kernel (thermal or hardware events)"},
}

// canarySymbol is a kernel string with known content, read with the others.
const canarySymbol = "linux_banner"

// Cell compares the kernel's copy of each usermode helper with what procfs
// and sysfs show, and checks the program each one names.
type Cell struct {
	root      string // prefixes paths (tests use a fixture tree)
	mountinfo string
}

// New returns the usermode helper Cell.
func New() *Cell { return &Cell{mountinfo: "/proc/self/mountinfo"} }

func (*Cell) ID() string                    { return "usermode_helpers" }
func (*Cell) Name() string                  { return "Kernel Usermode Helper Audit" }
func (*Cell) Timeout() time.Duration        { return 15 * time.Second }
func (*Cell) Supported(env *core.Env) error { return nil }
func (*Cell) Description() string {
	return "Compares the programs the kernel runs as root (modprobe, the core dump pipe, the hotplug helper, poweroff, cgroup release agents) in kernel memory with /proc/sys and /sys, and checks where each program lives and who can replace it"
}

// setting is one helper's value in each view.
type setting struct {
	helper
	user, kernel string
	haveUser     bool
	haveKernel   bool
}

func (c *Cell) path(p string) string { return filepath.Join(c.root, p) }

func (c *Cell) readUser(h helper) (string, bool) {
	data, err := fsutil.ReadFileNoAtime(c.path(h.file))
	if err != nil {
		return "", false
	}
	return strings.TrimSuffix(string(data), "\n"), true
}

func (c *Cell) Run(ctx context.Context, env *core.Env, rec *core.Recorder) error {
	settings := make([]setting, 0, len(helpers))
	for _, h := range helpers {
		s := setting{helper: h}
		s.user, s.haveUser = c.readUser(h)
		settings = append(settings, s)
	}

	suspicious := 0
	kernelRead := false
	if c.root == "" {
		n, err := c.compareKernel(env, rec, settings)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			rec.Limit("The kernel's own copy of the usermode helpers was not read: %v", err)
		}
		kernelRead = err == nil
		suspicious += n
	}

	examine := c.examiner(rec)
	for _, s := range settings {
		value := s.user
		if s.haveKernel {
			value = s.kernel // what the kernel will actually run
		} else if !s.haveUser {
			continue
		}
		prog := program(s.name, value)
		if prog == "" {
			continue
		}
		suspicious += examine(prog, s.name+" ("+s.file+")", s.trigger, map[string]string{"setting": s.file, "value": value})
	}
	suspicious += c.checkReleaseAgents(rec, examine)

	switch {
	case suspicious > 0:
		rec.Message("%d suspicious usermode helper(s)", suspicious)
	case kernelRead:
		rec.Message("Helpers match kernel, root-controlled")
	default:
		rec.Message("Helpers are root-controlled")
	}
	return nil
}

// program returns the program a helper setting runs, or "" when it runs none.
func program(name, value string) string {
	v := strings.TrimSpace(value)
	if name == "core_pattern" {
		if !strings.HasPrefix(v, "|") {
			return "" // a file name pattern: cores are written, nothing runs
		}
		v = strings.TrimSpace(strings.TrimPrefix(v, "|"))
	}
	if f := strings.Fields(v); len(f) > 0 {
		return f[0]
	}
	return ""
}

// compareKernel reads each helper from kernel memory and reports those whose
// procfs/sysfs value differs. It fills the kernel side of settings.
func (c *Cell) compareKernel(env *core.Env, rec *core.Recorder, settings []setting) (int, error) {
	if env.Lockdown == "confidentiality" {
		return 0, errors.New("kernel lockdown (confidentiality)")
	}
	ks, err := env.Kallsyms()
	if err != nil {
		return 0, err
	}
	img, err := ks.Image()
	if err != nil {
		return 0, err
	}
	if !img.HasData {
		return 0, errors.New("/proc/kallsyms lists no data symbols (CONFIG_KALLSYMS_ALL is off)")
	}
	type read struct {
		idx  int // into settings, or -1 for the canary
		addr uint64
		size uint32
	}
	var reads []read
	if a, ok := ks.Addr(canarySymbol); ok && !img.InText(a, 1) && img.InImage(a, strLen) {
		// Stay inside the page: the banner may end just before an unmapped one.
		reads = append(reads, read{-1, a, min(strLen, uint32(4096-a%4096))})
	}
	for i, s := range settings {
		a, ok := ks.Addr(s.symbol)
		switch {
		case !ok:
			if s.haveUser {
				rec.Limit("%s not read from kernel memory: %s is not in /proc/kallsyms", s.file, s.symbol)
			}
			continue
		case img.InText(a, 1) || !img.InImage(a, uint64(s.size)):
			// A data symbol in the text, or outside the image: kallsyms is being rewritten.
			rec.Suspicious(core.Finding{
				Description: fmt.Sprintf("/proc/kallsyms places %s at %#x, outside the kernel's data", s.symbol, a),
				Details:     map[string]string{"symbol": s.symbol, "address": fmt.Sprintf("%#x", a), "kernel_image": fmt.Sprintf("%#x-%#x", img.TextStart, img.End)},
				Why:         "This variable is part of the core kernel image's data. A different address means /proc/kallsyms is being rewritten to mislead scanners.",
				Benign:      "None expected.",
			})
			continue
		}
		reads = append(reads, read{i, a, s.size})
	}
	if len(reads) == 0 {
		return 0, errors.New("none of the helper variables is in /proc/kallsyms")
	}

	mem, err := kmem.Open(env)
	if err != nil {
		return 0, err
	}
	defer mem.Close()
	if id := mem.ProgramID(); id != 0 {
		rec.Footprint("bpf_prog_id", strconv.FormatUint(uint64(id), 10))
	}
	type kstr struct {
		s  string
		ok bool
	}
	readAll := func() ([]kstr, error) {
		reqs := make([]kmem.Req, len(reads))
		for i, r := range reads {
			reqs[i] = kmem.Req{Addr: r.addr, Len: int(r.size)}
		}
		got, err := mem.Read(reqs)
		if err != nil {
			return nil, err
		}
		out := make([]kstr, len(got))
		for i, b := range got {
			switch {
			case b == nil:
			case reads[i].idx < 0: // the canary is checked by its prefix and may be longer than the read
				out[i].s, out[i].ok = kmem.Prefix(b)
			default:
				out[i].s, out[i].ok = kmem.String(b)
			}
		}
		return out, nil
	}

	got, err := readAll()
	if err != nil {
		return 0, err
	}
	var mismatched []int
	for i, r := range reads {
		v, ok := got[i].s, got[i].ok
		if r.idx < 0 {
			rec.Canary(canarySymbol, "kernel memory read by BPF", ok && strings.HasPrefix(v, "Linux version "))
			continue
		}
		if !ok {
			rec.Limit("%s could not be read from kernel memory", settings[r.idx].symbol)
			continue
		}
		s := &settings[r.idx]
		s.kernel, s.haveKernel = v, true
		if s.haveUser && s.user != v {
			mismatched = append(mismatched, i)
		}
	}
	if len(mismatched) == 0 {
		return 0, nil
	}

	// Re-read both views: a value written during the scan is not a lie.
	again, err := readAll()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, i := range mismatched {
		s := &settings[reads[i].idx]
		k2, ok := again[i].s, again[i].ok
		u2, uok := c.readUser(s.helper)
		if !ok || !uok || k2 != s.kernel || u2 != s.user || u2 == k2 {
			continue
		}
		n++
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("%s shows %q, but the kernel's %s holds %q", s.file, s.user, s.symbol, s.kernel),
			Details:     map[string]string{"setting": s.file, "shown": s.user, "kernel": s.kernel, "symbol": s.symbol},
			Why: "The kernel renders " + s.file + " straight from " + s.symbol + ", so the two always match. A difference " +
				"means the read is filtered to hide the program the kernel really runs as root " + s.trigger + ".",
			Benign: "None expected: both views were read twice.",
		})
	}
	return n, nil
}

// systemDirs hold programs installed by the distribution's packages.
var systemDirs = []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32"}

func under(p, dir string) bool { return p == dir || strings.HasPrefix(p, dir+"/") }

func inSystemDir(p string) bool {
	if under(p, "/usr/local") {
		return false
	}
	for _, d := range systemDirs {
		if under(p, d) {
			return true
		}
	}
	return false
}

// location says why a helper's path is an unusual place for a root program.
func location(p string) string {
	switch {
	case under(p, "/dev/shm"), under(p, "/run/shm"):
		return "a memory-backed directory"
	case under(p, "/run") && !nixRun(p):
		return "a memory-backed directory (/run)"
	case under(p, "/tmp"), under(p, "/var/tmp"):
		return "a temporary directory"
	}
	for _, part := range strings.Split(filepath.Dir(p), "/") {
		if strings.HasPrefix(part, ".") && part != "." && part != ".." {
			return "a hidden directory"
		}
	}
	return ""
}

// nixRun reports NixOS paths under /run that lead into /nix/store
// (NixOS sets modprobe to /run/current-system/sw/bin/modprobe).
func nixRun(p string) bool {
	for _, d := range []string{"/run/current-system", "/run/booted-system", "/run/wrappers"} {
		if under(p, d) {
			return true
		}
	}
	return false
}

// examiner returns a function that checks one helper program and records
// what it finds; it returns the number of suspicious findings. The kernel
// runs helpers in the initial mount namespace, so their files are only
// examined when zygarde shares init's root directory.
func (c *Cell) examiner(rec *core.Recorder) func(prog, source, trigger string, extra map[string]string) int {
	sameRoot := c.root != "" || fsutil.SameAsHostRoot("/proc/1/root")
	limited := false
	// When the base system itself (/bin/sh) can be replaced by a user other than
	// root, one helper being replaceable the same way says nothing about it.
	baseline := ""
	if sameRoot {
		baseline = fsutil.ControlledBy(c.root, "/bin/sh")
	}
	baselineNoted := false
	var owners map[string]string
	var ownerSource string
	ownersRead := false

	return func(prog, source, trigger string, extra map[string]string) int {
		d := map[string]string{"program": prog}
		for k, v := range extra {
			d[k] = v
		}
		suspicious := func(why, benign string) int {
			if c.root == "" {
				fsutil.MergeMetadata(d, "file_", fsutil.FileMetadata(prog))
			}
			rec.Suspicious(core.Finding{
				Description: fmt.Sprintf("The kernel runs %s as root through %s: %s", prog, source, why),
				Details:     d,
				Why: "The kernel starts this program itself, as root, outside any user session, " + trigger + ". Pointing a " +
					"usermode helper at their own program gives an attacker root code execution on demand and a " +
					"persistence that no crontab, service or shell profile shows (a classic privilege escalation " +
					"and container escape target).",
				Benign: benign,
			})
			return 1
		}
		if !filepath.IsAbs(prog) {
			rec.Observe(fmt.Sprintf("%s names %s, which is not an absolute path: the kernel cannot run it", source, prog), d)
			return 0
		}
		if why := location(prog); why != "" {
			d["reason"] = why
			return suspicious("it lives in "+why, "None expected for a program the kernel runs as root.")
		}
		if !sameRoot {
			if !limited {
				rec.Limit("Helper programs not examined: zygarde does not share init's root directory (a container)")
				limited = true
			}
			rec.Observe(fmt.Sprintf("The kernel runs %s as root through %s (file not examined)", prog, source), d)
			return 0
		}
		full := c.path(prog)
		var st unix.Stat_t
		if err := unix.Stat(full, &st); err != nil {
			rec.Observe(fmt.Sprintf("%s names %s, which does not exist", source, prog), d)
			return 0
		}
		if found, err := fsutil.InListing(filepath.Dir(full), filepath.Base(full)); err == nil && !found {
			d["reason"] = "hidden from its directory listing"
			return suspicious("it is hidden from its directory listing", "None expected.")
		}
		if why := fsutil.ControlledBy(c.root, prog); why != "" && baseline != "" {
			if !baselineNoted {
				rec.Limit("Ownership of usermode helper programs not judged: /bin/sh can be replaced by a user other than root too (%s)", baseline)
				baselineNoted = true
			}
		} else if why != "" {
			d["reason"] = why
			return suspicious(why+", so a user other than root can replace it",
				"A program installed with loose permissions. Check who owns it and its directories.")
		}
		real, err := filepath.EvalSymlinks(full)
		if err == nil && c.root != "" {
			if r, rerr := filepath.Rel(c.root, real); rerr == nil {
				real = "/" + filepath.ToSlash(r)
			}
		}
		if err == nil && real != prog {
			d["resolves_to"] = real
		}
		if err == nil && inSystemDir(real) {
			if !ownersRead {
				ownersRead = true
				owners, ownerSource, err = c.allOwners()
				if err != nil {
					rec.Limit("Usermode helper programs not checked against the package database: %v", err)
				}
			}
			if owners != nil {
				if pkg := owners[real]; pkg != "" {
					d["package"] = pkg
				} else {
					d["reason"] = "belongs to no installed package"
					d["package_manager"] = ownerSource
					return suspicious(fmt.Sprintf("%s is in a system directory but belongs to no installed package", real),
						"Software installed outside the package manager. Check who installed the file (times, contents).")
				}
			}
		}
		rec.Observe(fmt.Sprintf("The kernel runs %s as root through %s", prog, source), d)
		return 0
	}
}

// allOwners looks up the package owning every helper program at once.
func (c *Cell) allOwners() (map[string]string, string, error) {
	wanted := map[string]bool{}
	for _, h := range helpers {
		if v, ok := c.readUser(h); ok {
			if p := program(h.name, v); p != "" {
				if r, err := filepath.EvalSymlinks(c.path(p)); err == nil {
					if c.root != "" {
						if rel, err := filepath.Rel(c.root, r); err == nil {
							r = "/" + filepath.ToSlash(rel)
						}
					}
					wanted[r] = true
				}
			}
		}
	}
	for _, a := range c.releaseAgents() {
		if r, err := filepath.EvalSymlinks(c.path(a.agent)); err == nil {
			if c.root != "" {
				if rel, err := filepath.Rel(c.root, r); err == nil {
					r = "/" + filepath.ToSlash(rel)
				}
			}
			wanted[r] = true
		}
	}
	return pkgdb.Owners(c.root, wanted)
}

type releaseAgent struct {
	mount, file, agent string
}

// releaseAgents lists the release agents of the mounted cgroup v1 hierarchies.
// The kernel runs a hierarchy's agent when a cgroup with notify_on_release
// set becomes empty.
func (c *Cell) releaseAgents() []releaseAgent {
	f, err := fsutil.OpenNoAtime(c.path(c.mountinfo))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []releaseAgent
	seen := map[string]bool{}
	sc := fsutil.NewScanner(f)
	for sc.Scan() {
		// id parent major:minor root mountpoint options [optional...] - fstype source superopts
		pre, post, ok := strings.Cut(sc.Text(), " - ")
		if !ok {
			continue
		}
		pf, qf := strings.Fields(pre), strings.Fields(post)
		if len(pf) < 5 || len(qf) < 1 || qf[0] != "cgroup" || pf[3] != "/" {
			continue // only the root of a v1 hierarchy has a release_agent file
		}
		file := filepath.Join(unescape(pf[4]), "release_agent")
		if seen[file] {
			continue
		}
		seen[file] = true
		data, err := fsutil.ReadFileNoAtime(c.path(file))
		if err != nil {
			continue
		}
		if a := strings.TrimSpace(string(data)); a != "" {
			out = append(out, releaseAgent{unescape(pf[4]), file, a})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].file < out[j].file })
	return out
}

// unescape decodes the octal escapes (\040 for a space) of mountinfo fields.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func (c *Cell) checkReleaseAgents(rec *core.Recorder, examine func(prog, source, trigger string, extra map[string]string) int) int {
	n := 0
	for _, a := range c.releaseAgents() {
		prog := program("release_agent", a.agent)
		n += examine(prog, "the cgroup release agent ("+a.file+")",
			"when a cgroup of that hierarchy with notify_on_release set becomes empty (a known container escape: a "+
				"process that can write release_agent runs any program on the host)",
			map[string]string{"setting": a.file, "value": a.agent, "hierarchy": a.mount})
	}
	return n
}
