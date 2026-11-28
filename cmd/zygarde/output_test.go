// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/kernel"
	"github.com/waldh4ri/zygarde/internal/report"
)

func result(cell, name string, s core.Status, msg string) core.Result {
	r := core.Result{Cell: cell, Name: name, Message: msg, DurationSeconds: 0.2}
	r.SetStatus(s)
	return r
}

// render prints a report the way a run would, without colors.
func render(t *testing.T, results []core.Result) string {
	t.Helper()
	return renderAt(t, levelNormal, style{}, results)
}

// renderAt prints a report at a verbosity level and style.
func renderAt(t *testing.T, level int, st style, results []core.Result) string {
	t.Helper()
	var buf bytes.Buffer
	p := newPrinter(&buf, false, level, st, 100)
	rep := &report.Report{Host: report.Host{Hostname: "web-01", Distro: "Ubuntu 24.04.5 LTS", Kernel: "6.8.0-142-generic", Arch: "amd64", Lockdown: "none", BTF: true}}
	var cells []core.Cell
	p.header(rep, cells)
	p.total = len(results)
	for _, r := range results {
		p.index++
		p.nameW = max(p.nameW, len(r.Name))
	}
	p.index = 0
	for _, r := range results {
		p.index++
		p.result(r)
	}
	rep.Finish(results)
	p.summary(rep, "report.json")
	t.Log("\n" + buf.String())
	return buf.String()
}

func TestRenderSuspicious(t *testing.T) {
	file := result("hidden_file", "Hidden File Detection", core.StatusSuspicious, "")
	file.Findings = []core.Finding{{
		Description: "/usr/lib/.cache exists but is filtered out of directory listings",
		Details:     map[string]string{"path": "/usr/lib/.cache", "directory": "/usr/lib", "inode": "4242", "owner": "nobody"},
		Why:         "The filesystem returned this entry, but it was removed before the listing reached userspace.",
		Benign:      "Rare: some security products hide their own files this way.",
	}}
	proc := result("hidden_process", "Hidden Process Detection", core.StatusOK, "No hidden processes")
	proc.Limitations = []string{"Scheduler view not run: zygarde is not in the initial PID namespace"}
	out := render(t, []core.Result{
		result("ebpf_integrity", "eBPF Integrity", core.StatusOK, "bpf() works normally"),
		result("altered_syscall_table", "Syscall Table Integrity", core.StatusSkipped, "this kernel dispatches syscalls through x64_sys_call()"),
		proc,
		file,
	})
	for _, want := range []string{
		"web-01", "Ubuntu 24.04.5 LTS",
		"SUSPICIOUS", "1 finding(s), see below",
		"FINDINGS", "/usr/lib/.cache exists", "Evidence", "owner=nobody", "Key evidence only", "Why", "Rule out",
		"OK*", "Partly checked (*)", "Not checked on this system",
		"Exit code 2", "Report saved to report.json",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	if strings.Contains(out, "NEXT STEPS") {
		t.Error("output must not print a next-steps section")
	}
	if strings.Contains(out, "\033[") {
		t.Error("colors must be off when disabled")
	}
}

func TestRenderClean(t *testing.T) {
	out := render(t, []core.Result{result("kernel_taint", "Kernel Taint Consistency", core.StatusOK, "Kernel is not tainted")})
	for _, want := range []string{"CLEAN", "Exit code 0"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	if strings.Contains(out, "FINDINGS") {
		t.Error("clean report must not have a findings section")
	}
}

// Findings of one kind share a single Why/Rule out note, and every table line
// has the same width, within the output width, even with long paths.
func TestFindingsTable(t *testing.T) {
	lib := "/app/node_modules/.pnpm/bcrypt@6.0.0/node_modules/bcrypt/prebuilds/linux-x64/bcrypt.glibc.node"
	hooks := result("userhooks", "Userspace Hook Detection", core.StatusSuspicious, "")
	for _, l := range []string{lib, lib + "2", lib + "3"} {
		hooks.Findings = append(hooks.Findings, core.Finding{
			Description: "Executable library " + l + " (mapped from a hidden directory) is mapped into 1 process(es)",
			Details:     map[string]string{"library": l, "pids": "545826"},
			Why:         "Inspecting /proc/<pid>/maps found executable code mapped from a hidden location.",
			Benign:      "JIT or FFI runtimes.",
		})
	}
	for _, width := range []int{100, 80} {
		var buf bytes.Buffer
		p := newPrinter(&buf, false, levelNormal, style{}, width)
		rep := &report.Report{}
		rep.Finish([]core.Result{hooks})
		p.findings(rep)
		out := buf.String()
		t.Log("\n" + out)
		if n := strings.Count(out, "Why"); n != 1 {
			t.Errorf("width %d: Why printed %d times, want once", width, n)
		}
		if !strings.Contains(out, "1-3. Userspace Hook Detection") {
			t.Errorf("width %d: note does not name findings 1-3", width)
		}
		tableW := 0
		for _, line := range strings.Split(out, "\n") {
			if !strings.HasPrefix(line, "  ┌") && !strings.HasPrefix(line, "  │") &&
				!strings.HasPrefix(line, "  ├") && !strings.HasPrefix(line, "  └") {
				continue
			}
			n := utf8.RuneCountInString(line)
			if tableW == 0 {
				tableW = n
			}
			if n != tableW || n > width {
				t.Errorf("width %d: table line is %d wide (table %d): %q", width, n, tableW, line)
			}
		}
		if tableW == 0 {
			t.Fatalf("width %d: no table printed", width)
		}
	}
}

func TestWrapCell(t *testing.T) {
	for _, tc := range []struct {
		text  string
		width int
		want  []string
	}{
		{"a bb ccc", 4, []string{"a bb", "ccc"}},
		{"k=1\nk=2", 10, []string{"k=1", "k=2"}},
		{"/usr/lib/x86_64/libfoo.so", 12, []string{"/usr/lib/", "x86_64/", "libfoo.so"}},
		{"abcdefghij", 4, []string{"abcd", "efgh", "ij"}},
		{"", 5, []string{""}},
	} {
		if got := wrapCell(tc.text, tc.width); strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("wrapCell(%q, %d) = %q, want %q", tc.text, tc.width, got, tc.want)
		}
	}
}

func TestNumberRanges(t *testing.T) {
	for want, ns := range map[string][]int{"1": {1}, "1-3": {1, 2, 3}, "1-2, 4, 6-7": {1, 2, 4, 6, 7}} {
		if got := numberRanges(ns); got != want {
			t.Errorf("numberRanges(%v) = %q, want %q", ns, got, want)
		}
	}
}

func TestWrapped(t *testing.T) {
	var buf bytes.Buffer
	p := newPrinter(&buf, false, levelNormal, style{}, 40)
	p.wrapped("  - ", strings.Repeat("word ", 20), nil)
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if len(line) > 40 {
			t.Errorf("line exceeds width: %q", line)
		}
		if !strings.HasPrefix(line, "  ") {
			t.Errorf("continuation not indented: %q", line)
		}
	}
}

// Checks that kptr_restrict skipped or limited are named once, with the fix;
// other skips and limitations keep their own lines.
func TestKptrCoverage(t *testing.T) {
	hidden := "kernel addresses hidden (kptr_restrict=2)"
	inline := result("inline_hook", "Inline Hook Detection", core.StatusSkipped, hidden)
	netf := result("netfilter", "Netfilter Hook Inventory", core.StatusSkipped, hidden)
	sct := result("altered_syscall_table", "Syscall Table Integrity", core.StatusSkipped, "this kernel dispatches syscalls through x64_sys_call()")
	mods := result("hidden_kernel_module", "Hidden Kernel Module Detection", core.StatusOK, "")
	mods.Limitations = []string{"Kernel memory views of the modules were not compared: " + hidden, "Module memory in /proc/vmallocinfo was not compared"}
	render := func(v *int, results ...core.Result) string {
		var buf bytes.Buffer
		p := newPrinter(&buf, false, levelNormal, style{}, 100)
		rep := &report.Report{Host: report.Host{KptrRestrict: v}}
		rep.Finish(results)
		p.summary(rep, "")
		t.Log("\n" + buf.String())
		return buf.String()
	}
	two := 2
	out := render(&two, inline, sct, netf, mods)
	for _, want := range []string{
		"kernel.kptr_restrict=2 hides kernel addresses, even from root:",
		"- Not checked: Inline Hook Detection, Netfilter Hook Inventory",
		"- Partly checked (*): Hidden Kernel Module Detection",
		"To cover them: sysctl -w kernel.kptr_restrict=1, run Zygarde, then set it back to 2.",
		"Syscall Table Integrity: this kernel dispatches",
		"Hidden Kernel Module Detection: Module memory in /proc/vmallocinfo",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("coverage lacks %q", want)
		}
	}
	if strings.Contains(out, hidden) {
		t.Error("coverage repeats the kptr_restrict reason per check")
	}
	if out := render(&two, sct); strings.Contains(out, "kptr_restrict") {
		t.Error("no affected check should print the kptr_restrict block")
	}
}

// Lockdown is grouped like kptr_restrict, in its own block.
func TestLockdownCoverage(t *testing.T) {
	lock := "kernel lockdown (confidentiality)"
	inline := result("inline_hook", "Inline Hook Detection", core.StatusSkipped, lock)
	hooks := result("userhooks", "Userspace Hook Detection", core.StatusOK, "")
	hooks.Limitations = []string{"Executable mappings not compared with the kernel's: " + lock}
	var buf bytes.Buffer
	p := newPrinter(&buf, false, levelNormal, style{}, 100)
	rep := &report.Report{}
	rep.Finish([]core.Result{inline, hooks})
	p.summary(rep, "")
	out := buf.String()
	t.Log("\n" + out)
	for _, want := range []string{
		"Kernel lockdown (confidentiality) blocks reading kernel memory:",
		"- Not checked: Inline Hook Detection",
		"- Partly checked (*): Userspace Hook Detection",
		"boot without lockdown=confidentiality",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("coverage lacks %q", want)
		}
	}
	if strings.Contains(out, "Not checked on this system") || strings.Contains(out, "mappings not compared") {
		t.Error("lockdown causes must not also be listed one by one")
	}
}

func TestSymbolsUnavailableSkips(t *testing.T) {
	if st, _ := core.Classify(nil, core.SymbolsUnavailable(kernel.HiddenAddressesError())); st != core.StatusSkipped {
		t.Errorf("hidden kallsyms addresses: status %v, want SKIPPED", st)
	}
}

func suspiciousFile() core.Result {
	r := result("hidden_file", "Hidden File Detection", core.StatusSuspicious, "")
	r.Findings = []core.Finding{{
		Description: "/usr/lib/.cache exists but is filtered out of directory listings",
		Details:     map[string]string{"path": "/usr/lib/.cache", "inode": "4242", "owner": "nobody", "uid": "0"},
		Why:         "Removed before the listing reached userspace.",
	}}
	return r
}

// The default report keeps key evidence; -v shows every field.
func TestEvidenceLevels(t *testing.T) {
	normal := renderAt(t, levelNormal, style{}, []core.Result{suspiciousFile()})
	for _, want := range []string{"owner=nobody", "uid=0", "Key evidence only"} {
		if !strings.Contains(normal, want) {
			t.Errorf("default report lacks %q", want)
		}
	}
	for _, hidden := range []string{"inode=4242", "path=/usr/lib/.cache"} {
		if strings.Contains(normal, hidden) {
			t.Errorf("default report shows secondary or restated evidence %q", hidden)
		}
	}
	verbose := renderAt(t, levelVerbose, style{}, []core.Result{suspiciousFile()})
	for _, want := range []string{"inode=4242", "path=/usr/lib/.cache", "owner=nobody"} {
		if !strings.Contains(verbose, want) {
			t.Errorf("-v report lacks %q", want)
		}
	}
	if strings.Contains(verbose, "Key evidence only") {
		t.Error("-v report must not say evidence was shortened")
	}
}

// -q prints the verdict and one line per finding: no header, table or coverage.
func TestQuiet(t *testing.T) {
	out := renderAt(t, levelQuiet, style{}, []core.Result{
		result("ebpf_integrity", "eBPF Integrity", core.StatusOK, "bpf() works normally"),
		suspiciousFile(),
	})
	for _, want := range []string{"SUSPICIOUS", "1. Hidden File Detection: /usr/lib/.cache exists", "2 of 2 checks completed.", "Report saved to report.json"} {
		if !strings.Contains(out, want) {
			t.Errorf("-q output lacks %q", want)
		}
	}
	for _, not := range []string{"web-01", "eBPF Integrity", "FINDINGS", "COVERAGE", "┌", "Why"} {
		if strings.Contains(out, not) {
			t.Errorf("-q output contains %q", not)
		}
	}
}

// Colors use pastel truecolor when available, 256 colors otherwise, and the
// table keeps its alignment either way.
func TestColors(t *testing.T) {
	for _, st := range []style{{on: true, truecolor: true}, {on: true}} {
		out := renderAt(t, levelNormal, st, []core.Result{suspiciousFile()})
		want := "\033[1;38;5;235;48;5;211m SUSPICIOUS "
		if st.truecolor {
			want = "\033[1;38;2;30;30;46;48;2;243;139;168m SUSPICIOUS "
		}
		if !strings.Contains(out, want) {
			t.Errorf("truecolor=%v: no SUSPICIOUS badge %q", st.truecolor, want)
		}
		tableW := 0
		for _, line := range strings.Split(out, "\n") {
			if !strings.Contains(line, "│") && !strings.Contains(line, "─") {
				continue
			}
			n := visibleLen(line)
			if tableW == 0 {
				tableW = n
			}
			if n != tableW {
				t.Errorf("truecolor=%v: table line %d wide, want %d: %q", st.truecolor, n, tableW, line)
			}
		}
	}
}

// Segments keep their own style when wrapped, and lines stay within width.
func TestWrapSegs(t *testing.T) {
	var buf bytes.Buffer
	p := newPrinter(&buf, false, levelNormal, style{on: true}, 40)
	p.wrapSegs("  ", seg{strings.Repeat("alpha ", 8), p.st.bold}, seg{"(0.2s)", p.st.dim})
	out := buf.String()
	t.Log("\n" + out)
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if visibleLen(line) > 40 {
			t.Errorf("line exceeds width: %q", line)
		}
	}
	if !strings.Contains(out, p.st.dim("(0.2s)")) {
		t.Error("tail segment lost its style")
	}
}

func TestVerbosityFlags(t *testing.T) {
	for _, c := range []struct {
		args  []string
		level int
		debug bool
	}{
		{nil, levelNormal, false},
		{[]string{"-q"}, levelQuiet, false},
		{[]string{"-v"}, levelVerbose, false},
		{[]string{"-v", "-v"}, levelDebug, true},
		{[]string{"-vv"}, levelDebug, true},
		{[]string{"--debug"}, levelDebug, true},
	} {
		o, err := parseFlags(c.args)
		if err != nil {
			t.Fatalf("%v: %v", c.args, err)
		}
		if o.level() != c.level || o.debug != c.debug {
			t.Errorf("%v: level %d debug %v, want %d %v", c.args, o.level(), o.debug, c.level, c.debug)
		}
	}
	if _, err := parseFlags([]string{"-q", "-v"}); err == nil {
		t.Error("-q -v must be refused")
	}
}

// fetchBTF stays off the network when it has nothing to do, and says why.
func TestFetchBTFSkips(t *testing.T) {
	args := []string{"-q"}
	o := options{}
	o.settings.BTFPath = "/x.btf"
	rep := &report.Report{Host: report.Host{BTFSource: "none"}}
	fetchBTF(context.Background(), &o, rep, &args)()
	if rep.Host.BTFSource != "file" || rep.Host.BTFHub != nil || len(args) != 1 {
		t.Errorf("--btf: source %q, btfhub %+v, args %v", rep.Host.BTFSource, rep.Host.BTFHub, args)
	}

	o = options{}
	rep = &report.Report{Host: report.Host{BTF: true, BTFSource: "kernel"}}
	fetchBTF(context.Background(), &o, rep, &args)()
	if rep.Host.BTFSource != "kernel" || rep.Host.BTFHub != nil {
		t.Errorf("kernel BTF: source %q, btfhub %+v", rep.Host.BTFSource, rep.Host.BTFHub)
	}

	// Without --btfhub: nothing is downloaded, only the hint is recorded.
	o = options{}
	rep = &report.Report{Host: report.Host{BTFSource: "none"}}
	fetchBTF(context.Background(), &o, rep, &args)()
	if rep.Host.BTFHub == nil || rep.Host.BTFHub.Requested || rep.Host.BTFHub.Verified || o.settings.BTFPath != "" || len(args) != 1 {
		t.Errorf("no --btfhub: %+v, args %v", rep.Host.BTFHub, args)
	}
	if rep.ScannerFootprint != nil && len(rep.ScannerFootprint.Artifacts) != 0 {
		t.Errorf("no --btfhub must not touch the network: %v", rep.ScannerFootprint.Artifacts)
	}
}

// The header says where BTF came from, or why it is missing.
func TestHeaderBTF(t *testing.T) {
	for _, c := range []struct {
		host report.Host
		want []string
	}{
		{report.Host{BTFSource: "btfhub", BTFHub: &report.BTFHub{Requested: true, Path: "ubuntu/20.04/x86_64/5.4.0-72-generic.btf.tar.xz", GitBlobSHA1: "59d40cd9", Verified: true}},
			[]string{"BTF from BTFHub", "ubuntu/20.04/x86_64/5.4.0-72-generic.btf.tar.xz", "59d40cd9"}},
		{report.Host{BTFSource: "none", BTFHub: &report.BTFHub{Requested: true, Path: "ubuntu/20.04/x86_64/x.btf.tar.xz", Error: "BTFHub publishes no BTF for this kernel"}},
			[]string{"BTF no", "not fetched from BTFHub: BTFHub publishes no BTF for this kernel.", "--btf <file>"}},
		{report.Host{BTFSource: "none", BTFHub: &report.BTFHub{Path: "ubuntu/20.04/x86_64/5.4.0-72-generic.btf.tar.xz"}},
			[]string{"BTF no", "Run with --btfhub to fetch", "ubuntu/20.04/x86_64/5.4.0-72-generic.btf.tar.xz"}},
		{report.Host{BTFSource: "none", BTFHub: &report.BTFHub{Error: "not mapped"}},
			[]string{"BTF no", "BTFHub has no BTF for this distribution"}},
		{report.Host{BTFSource: "file"}, []string{"BTF from --btf"}},
	} {
		var buf bytes.Buffer
		p := newPrinter(&buf, false, levelNormal, style{}, 250)
		p.header(&report.Report{Host: c.host}, nil)
		for _, w := range c.want {
			if !strings.Contains(buf.String(), w) {
				t.Errorf("header lacks %q:\n%s", w, buf.String())
			}
		}
	}
}

// -q keeps the BTF notice when BTF is missing (it explains skipped checks),
// and drops it once BTFHub provided verified BTF.
func TestQuietBTFHint(t *testing.T) {
	for _, c := range []struct {
		b    *report.BTFHub
		want string // "" = no notice
	}{
		{&report.BTFHub{Path: "ubuntu/20.04/x86_64/5.4.0-72-generic.btf.tar.xz"}, "Run with --btfhub to fetch ubuntu/20.04/x86_64/5.4.0-72-generic.btf.tar.xz"},
		{&report.BTFHub{Requested: true, Error: "BTFHub publishes no BTF for this kernel"}, "not fetched from BTFHub"},
		{&report.BTFHub{Requested: true, Verified: true, Path: "x"}, ""},
		{nil, ""},
	} {
		var buf bytes.Buffer
		p := newPrinter(&buf, false, levelQuiet, style{}, 250)
		rep := &report.Report{Host: report.Host{BTFSource: "none", BTFHub: c.b}}
		rep.Finish([]core.Result{result("kernel_taint", "Kernel Taint Consistency", core.StatusOK, "")})
		p.summary(rep, "")
		out := buf.String()
		switch {
		case c.want == "" && strings.Contains(out, "BTF "):
			t.Errorf("%+v: unexpected BTF notice:\n%s", c.b, out)
		case c.want != "" && !strings.Contains(out, c.want):
			t.Errorf("%+v: -q output lacks %q:\n%s", c.b, c.want, out)
		}
	}
}

// Checks skipped for lack of BTF are named once, with how to provide it:
// --btfhub when BTFHub has the kernel, --btf otherwise.
func TestNoBTFCoverage(t *testing.T) {
	sct := result("altered_syscall_table", "Syscall Table Integrity", core.StatusSkipped, core.NoBTF)
	inline := result("inline_hook", "Inline Hook Detection", core.StatusSkipped, core.NoBTF)
	mods := result("hidden_kernel_module", "Hidden Kernel Module Detection", core.StatusOK, "")
	mods.Limitations = []string{"Kernel memory views of the modules were not compared: " + core.NoBTF}
	for _, c := range []struct {
		hub  *report.BTFHub
		want string
	}{
		{&report.BTFHub{Path: "ubuntu/20.04/x86_64/5.4.0-72-generic.btf.tar.xz"}, "run with --btfhub (BTFHub has this kernel)"},
		{&report.BTFHub{Requested: true, Error: "x"}, "BTFHub could not provide it"},
		{nil, "give BTF with --btf <file>"},
	} {
		var buf bytes.Buffer
		p := newPrinter(&buf, false, levelNormal, style{}, 200)
		rep := &report.Report{Host: report.Host{BTFSource: "none", BTFHub: c.hub}}
		rep.Finish([]core.Result{sct, inline, mods})
		p.summary(rep, "")
		out := buf.String()
		for _, w := range []string{
			"This kernel was built without BTF, which these checks need:",
			"- Not checked: Syscall Table Integrity, Inline Hook Detection",
			"- Partly checked (*): Hidden Kernel Module Detection",
			c.want,
		} {
			if !strings.Contains(out, w) {
				t.Errorf("%+v: coverage lacks %q:\n%s", c.hub, w, out)
			}
		}
		if strings.Count(out, core.NoBTF) != 0 {
			t.Errorf("%+v: the reason is repeated per check:\n%s", c.hub, out)
		}
	}
}
