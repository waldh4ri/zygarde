// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/report"
)

// Verbosity levels of the text report. The JSON report is always complete.
const (
	levelQuiet   = -1 // -q: verdict and one line per finding
	levelNormal  = 0  // per-check lines, findings with their key evidence, coverage
	levelVerbose = 1  // -v: check descriptions, observations, canaries, every evidence field
	levelDebug   = 2  // -vv: also debug logs on stderr
)

// A color is a soft pastel shade (Catppuccin Mocha), in 24-bit RGB with the
// closest xterm-256 index for terminals without truecolor.
type color struct {
	r, g, b uint8
	x256    uint8
}

var (
	cGreen  = color{166, 227, 161, 151}
	cYellow = color{249, 226, 175, 223}
	cPink   = color{243, 139, 168, 211}
	cPeach  = color{250, 179, 135, 216}
	cBlue   = color{137, 180, 250, 111}
	cMauve  = color{203, 166, 247, 183}
	cTeal   = color{148, 226, 213, 116}
	cGrey   = color{127, 132, 156, 245}
	cBase   = color{30, 30, 46, 235} // text on a colored badge
)

// style applies ANSI colors when enabled.
type style struct{ on, truecolor bool }

func (s style) code(c color, layer int) string { // layer 38: foreground, 48: background
	if s.truecolor {
		return fmt.Sprintf("%d;2;%d;%d;%d", layer, c.r, c.g, c.b)
	}
	return fmt.Sprintf("%d;5;%d", layer, c.x256)
}

func (s style) wrap(code, text string) string {
	if !s.on || text == "" {
		return text
	}
	return "\033[" + code + "m" + text + "\033[0m"
}
func (s style) fg(c color, t string) string     { return s.wrap(s.code(c, 38), t) }
func (s style) strong(c color, t string) string { return s.wrap("1;"+s.code(c, 38), t) }
func (s style) bold(t string) string            { return s.wrap("1", t) }
func (s style) dim(t string) string             { return s.fg(cGrey, t) }

// badge prints text as a colored label: " CLEAN " on a pastel background.
func (s style) badge(c color, t string) string {
	if !s.on {
		return t
	}
	return s.wrap("1;"+s.code(cBase, 38)+";"+s.code(c, 48), " "+t+" ")
}

// colorEnabled follows the usual conventions: only on a terminal, never with
// NO_COLOR set (https://no-color.org) or --no-color.
func colorEnabled(f *os.File, flagOff bool) bool {
	if flagOff || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	return isTerminal(f)
}

// truecolor reports whether the terminal advertises 24-bit color.
func truecolor() bool {
	c := os.Getenv("COLORTERM")
	return c == "truecolor" || c == "24bit"
}

// printer renders a scan for a person at a terminal, or only JSON at the end.
type printer struct {
	w     io.Writer
	json  bool
	level int
	st    style
	index int
	total int
	nameW int
	width int
}

func newPrinter(w io.Writer, jsonMode bool, level int, st style, width int) *printer {
	return &printer{w: w, json: jsonMode, level: level, st: st, width: width}
}

func (p *printer) verbose() bool { return p.level >= levelVerbose }
func (p *printer) quiet() bool   { return p.level <= levelQuiet }

func (p *printer) printf(format string, args ...any) { fmt.Fprintf(p.w, format, args...) }

func (p *printer) fatal(msg string) int {
	if p.json {
		enc := json.NewEncoder(p.w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]string{"tool": "zygarde", "version": version, "error": msg})
	} else {
		fmt.Fprintf(os.Stderr, "zygarde: %s\n", msg)
	}
	return 1
}

// header prints what is being scanned, so a saved transcript stands alone.
func (p *printer) header(r *report.Report, cells []core.Cell) {
	p.total = len(cells)
	for _, c := range cells {
		p.nameW = max(p.nameW, utf8.RuneCountInString(c.Name()))
	}
	if p.json || p.quiet() {
		return
	}
	h := r.Host
	// Settings that limit what Zygarde can see stand out; the rest stays plain.
	btf := "yes"
	switch h.BTFSource {
	case "btfhub":
		btf = "from BTFHub"
	case "file":
		btf = "from --btf"
	case "none":
		btf = p.st.fg(cYellow, "no")
	}
	lockdown := h.Lockdown
	if lockdown == "confidentiality" {
		lockdown = p.st.fg(cYellow, lockdown)
	}
	kptr := ""
	if h.KptrRestrict != nil {
		v := strconv.Itoa(*h.KptrRestrict)
		if *h.KptrRestrict >= 2 {
			v = p.st.fg(cYellow, v)
		}
		kptr = " · kptr_restrict " + v
	}
	label := func(s string) string { return p.st.dim(fmt.Sprintf("%-9s", s)) }
	p.printf("%s %s\n\n", p.st.strong(cMauve, "zygarde "+version), p.st.dim("· eBPF rootkit triage for Linux"))
	p.printf("  %s %s\n", label("Host"), p.st.bold(h.Hostname))
	p.printf("  %s %s · Linux %s · %s\n", label("System"), h.Distro, h.Kernel, h.Arch)
	p.printf("  %s BTF %s · lockdown %s%s\n", label("Kernel"), btf, lockdown, kptr)
	if b := h.BTFHub; b != nil {
		yellow := func(s string) string { return p.st.fg(cYellow, s) }
		lead := "  " + label("BTF") + " "
		switch {
		case b.Verified:
			p.wrapSegs(lead, seg{"BTFHub " + b.Path + ",", nil},
				seg{"verified against GitHub's git blob hash " + b.GitBlobSHA1, p.st.dim})
		case b.Requested:
			p.wrapSegs(lead, seg{"not fetched from BTFHub: " + b.Error + ".", yellow},
				seg{"Checks that need BTF are skipped; --btf <file> provides it.", p.st.dim})
		case b.Path != "":
			// The hint: this kernel lacks BTF, and BTFHub publishes a path for it.
			p.wrapSegs(lead, seg{"this kernel ships none, so checks that need it are skipped.", yellow},
				seg{"Run with --btfhub to fetch " + b.Path + " from BTFHub, or give one with --btf <file>.", nil})
		default:
			p.wrapSegs(lead, seg{"this kernel ships none, so checks that need it are skipped.", yellow},
				seg{"Give one with --btf <file> (BTFHub has no BTF for this distribution).", nil})
		}
	}
	p.printf("  %s %s\n\n", label("Started"), r.StartedAt.Format("2006-01-02 15:04:05 MST"))
}

func (p *printer) start(c core.Cell) {
	p.index++
	if p.json || !p.verbose() {
		return
	}
	p.printf("  %s\n", p.st.dim(fmt.Sprintf("[%02d/%02d] %s: %s", p.index, p.total, c.Name(), c.Description())))
}

// result prints one aligned line per Cell: status, then its summary.
func (p *printer) result(r core.Result) {
	if p.json || p.quiet() {
		return
	}
	name := fmt.Sprintf("%-*s", p.nameW, r.Name)
	text := r.StatusText
	if r.Status == core.StatusOK && len(r.Limitations) > 0 {
		text += "*" // partly checked; listed under Coverage
	}
	status := fmt.Sprintf("%-10s", text)
	summary := r.Message
	var paint func(string) string
	switch r.Status {
	case core.StatusOK:
		status = p.st.fg(cGreen, status)
	case core.StatusSkipped:
		status = p.st.dim(status)
		name = p.st.dim(name)
		paint = p.st.dim
	case core.StatusError:
		status = p.st.strong(cPeach, status)
		name = p.st.bold(name)
		summary = r.Error
		paint = func(s string) string { return p.st.fg(cPeach, s) }
	case core.StatusSuspicious:
		status = p.st.strong(cPink, status)
		name = p.st.bold(name)
		summary = fmt.Sprintf("%d finding(s), see below", len(r.Findings))
		paint = func(s string) string { return p.st.fg(cPink, s) }
	}
	timing := ""
	if r.Status != core.StatusSkipped {
		timing = fmt.Sprintf(" (%.1fs)", r.DurationSeconds)
	}
	prefix := fmt.Sprintf("  %s %s  %s ", p.st.dim(fmt.Sprintf("[%02d/%02d]", p.index, p.total)), name, status)
	if visibleLen(prefix)+utf8.RuneCountInString(summary+timing) <= p.width {
		p.wrappedTail(prefix, summary, timing, paint)
	} else {
		// Too long to sit beside the status: give it its own lines.
		p.printf("%s\n", strings.TrimRight(prefix, " "))
		p.wrappedTail("        ", summary, timing, paint)
	}

	if p.verbose() {
		for _, o := range r.Observations {
			p.printf("        %s\n", p.st.dim("· "+o.Description))
		}
		for _, c := range r.Canaries {
			mark := p.st.dim("seen")
			if !c.Observed {
				mark = p.st.strong(cPink, "MISSING")
			}
			p.printf("        %s %s\n", p.st.dim(fmt.Sprintf("canary %s in %s:", c.Canary, c.View)), mark)
		}
	}
}

// wrappedTail is wrapped followed by a grey tail (the timing).
func (p *printer) wrappedTail(prefix, text, tail string, paint func(string) string) {
	p.wrapSegs(prefix, seg{text, paint}, seg{tail, p.st.dim})
}

// summary prints findings, coverage and the verdict.
func (p *printer) summary(r *report.Report, savedTo string) {
	if p.json {
		p.writeJSON(r)
		return
	}

	var errs, skipped []core.Result
	completed := 0
	for _, res := range r.Results {
		switch res.Status {
		case core.StatusError:
			errs = append(errs, res)
		case core.StatusSkipped:
			skipped = append(skipped, res)
		default:
			completed++
		}
	}

	if p.quiet() {
		p.quietSummary(r, errs, completed, savedTo)
		return
	}

	if r.Findings > 0 {
		p.section("Findings")
		p.findings(r)
	}

	if len(errs) > 0 {
		p.section("Errors")
		for _, res := range errs {
			p.wrapSegs("  ", seg{res.Name + ":", p.st.bold}, seg{res.Error, func(s string) string { return p.st.fg(cPeach, s) }})
		}
	}

	p.section("Coverage")
	p.printf("  %d of %d checks completed.\n", completed, len(r.Results))
	causeSkipped := make([][]string, len(causes))
	causePartial := make([][]string, len(causes))
	header := false
	for _, res := range skipped {
		if i := causeOf(res.Message); i >= 0 {
			causeSkipped[i] = append(causeSkipped[i], res.Name)
			continue
		}
		if !header {
			p.printf("  Not checked on this system:\n")
			header = true
		}
		p.wrapSegs("    "+p.st.dim("-")+" ", seg{res.Name + ":", p.st.bold}, seg{res.Message, p.st.dim})
	}
	header = false
	for _, res := range r.Results {
		for _, l := range res.Limitations {
			if i := causeOf(l); i >= 0 {
				if !slices.Contains(causePartial[i], res.Name) {
					causePartial[i] = append(causePartial[i], res.Name)
				}
				continue
			}
			if !header {
				p.printf("  Partly checked (%s):\n", p.st.fg(cYellow, "*"))
				header = true
			}
			p.wrapSegs("    "+p.st.dim("-")+" ", seg{res.Name + ":", p.st.bold}, seg{l, p.st.dim})
		}
	}
	for i, c := range causes {
		p.causeCoverage(r, c, causeSkipped[i], causePartial[i])
	}

	p.section("Verdict")
	p.verdict(r, len(errs))

	if savedTo != "" {
		p.printf("\n  %s %s\n", p.st.dim("Report saved to"), savedTo)
	}
}

// verdict prints the one-line outcome, with the exit code it implies.
func (p *printer) verdict(r *report.Report, errs int) {
	switch r.Verdict {
	case report.VerdictSuspicious:
		cells := 0
		for _, res := range r.Results {
			if len(res.Findings) > 0 {
				cells++
			}
		}
		p.printf("  %s  %s\n", p.st.badge(cPink, "SUSPICIOUS"),
			p.st.fg(cPink, fmt.Sprintf("%d finding(s) in %d check(s).", r.Findings, cells))+p.st.dim(" Exit code 2."))
	case report.VerdictIncomplete:
		p.printf("  %s  %s\n", p.st.badge(cPeach, "INCOMPLETE"),
			fmt.Sprintf("no findings, but %d check(s) failed.", errs)+p.st.dim(" Exit code 1."))
	default:
		p.printf("  %s  %s\n", p.st.badge(cGreen, "CLEAN"),
			"no signs of hiding or tampering in the checks that ran."+p.st.dim(" Exit code 0."))
	}
}

// quietSummary is the whole -q report: the verdict, one line per finding and
// per failed check, and how much of the scan completed.
func (p *printer) quietSummary(r *report.Report, errs []core.Result, completed int, savedTo string) {
	p.verdict(r, len(errs))
	n := 0
	for _, res := range r.Results {
		for _, f := range res.Findings {
			n++
			p.wrapSegs(fmt.Sprintf("  %s ", p.st.strong(cPeach, fmt.Sprintf("%2d.", n))),
				seg{res.Name + ":", p.st.bold}, seg{f.Description, nil})
		}
	}
	for _, res := range errs {
		p.wrapSegs("  "+p.st.strong(cPeach, "ERR")+" ", seg{res.Name + ":", p.st.bold}, seg{res.Error, func(s string) string { return p.st.fg(cPeach, s) }})
	}
	note := ""
	if completed < len(r.Results) {
		note = " (run without -q to see what was not checked)"
	}
	p.printf("  %s\n", p.st.dim(fmt.Sprintf("%d of %d checks completed.%s", completed, len(r.Results), note)))
	if savedTo != "" {
		p.printf("  %s %s\n", p.st.dim("Report saved to"), savedTo)
	}
}

// findings prints one table row per finding, then what each kind of finding
// means and how to rule it out, once for all the rows it applies to.
func (p *printer) findings(r *report.Report) {
	type note struct {
		cell, why, benign string
		rows              []int
	}
	var rows [][]string
	var notes []*note
	shortened := false
	for _, res := range r.Results {
		for _, f := range res.Findings {
			n := len(rows) + 1
			var ev []string
			for _, k := range slices.Sorted(maps.Keys(f.Details)) {
				if !p.verbose() && !keyEvidence(f, k) {
					shortened = true
					continue
				}
				ev = append(ev, k+"="+f.Details[k])
			}
			rows = append(rows, []string{strconv.Itoa(n), res.Name, f.Description, strings.Join(ev, "\n")})
			if f.Why == "" && f.Benign == "" {
				continue
			}
			i := slices.IndexFunc(notes, func(x *note) bool { return x.cell == res.Name && x.why == f.Why && x.benign == f.Benign })
			if i < 0 {
				notes = append(notes, &note{cell: res.Name, why: f.Why, benign: f.Benign})
				i = len(notes) - 1
			}
			notes[i].rows = append(notes[i].rows, n)
		}
	}

	p.printf("\n")
	p.table([]string{"#", "Check", "Finding", "Evidence"}, rows)
	if shortened {
		p.printf("  %s\n", p.st.dim("Key evidence only: -v or the JSON report (-o) has every field."))
	}
	for _, n := range notes {
		p.printf("\n  %s %s\n", p.st.strong(cPeach, numberRanges(n.rows)+"."), p.st.bold(n.cell))
		if n.why != "" {
			p.labelled(cBlue, "Why", n.why)
		}
		if n.benign != "" {
			p.labelled(cGreen, "Rule out", n.benign)
		}
	}
}

// secondaryEvidence are detail fields that matter when working a finding but
// not when reading the report: times, inode and ownership numbers, hashes,
// raw addresses. The default report leaves them out; -v and JSON keep them.
var secondaryEvidence = map[string]bool{
	"atime": true, "ctime": true, "mtime": true, "started_at": true,
	"inode": true, "gid": true, "size": true, "mode": true, "state": true,
	"ppid": true, "global_tid": true, "global_tgid": true, "ifindex": true,
	"cgroup": true, "sha256": true, "exe_sha256": true,
	"struct_module": true, "expected_address": true, "syscall_number": true,
	"start_id": true,
}

// keyEvidence reports whether detail k of f belongs in the default report:
// not a secondary field, and not a value the finding's sentence already
// states (the PID, module or path it names). Short values ("0", "1") are
// always kept, since they are not reliably "stated" by a substring match.
func keyEvidence(f core.Finding, k string) bool {
	if secondaryEvidence[k] {
		return false
	}
	v := f.Details[k]
	return utf8.RuneCountInString(v) < 3 || !strings.Contains(f.Description, v)
}

// table prints a bordered table that fits the output width. The first column
// and the second (capped) take their content's width; the third and fourth
// share the rest 3:2. Cells wrap at spaces, and words too long for their
// column (paths) break after a slash where possible.
func (p *printer) table(head []string, rows [][]string) {
	w := make([]int, len(head))
	for i, h := range head {
		w[i] = utf8.RuneCountInString(h)
	}
	for _, row := range rows {
		for i := range 2 {
			w[i] = max(w[i], utf8.RuneCountInString(row[i]))
		}
	}
	w[1] = min(w[1], 16)
	free := p.width - 2 - 3*len(w) - 1 - w[0] - w[1] // indent, "│ " … " │" borders
	w[3] = max(free*2/5, 12)
	w[2] = max(free-w[3], 16)

	rule := func(l, m, r string) {
		parts := make([]string, len(w))
		for i, n := range w {
			parts[i] = strings.Repeat("─", n+2)
		}
		p.printf("  %s\n", p.st.dim(l+strings.Join(parts, m)+r))
	}
	// Each column's lines come pre-styled; padding uses the visible width.
	line := func(cells []string, header bool) {
		wrapped := make([][]string, len(w))
		height := 1
		for i, c := range cells {
			switch {
			case header:
				wrapped[i] = []string{p.st.strong(cBlue, c)}
			case i == 0:
				wrapped[i] = []string{p.st.strong(cPeach, c)}
			case i == 3:
				wrapped[i] = p.evidenceLines(c, w[i])
			default:
				wrapped[i] = wrapCell(c, w[i])
			}
			height = max(height, len(wrapped[i]))
		}
		bar := p.st.dim("│")
		for l := range height {
			var b strings.Builder
			b.WriteString("  " + bar)
			for i := range w {
				text := ""
				if l < len(wrapped[i]) {
					text = wrapped[i][l]
				}
				text += strings.Repeat(" ", max(w[i]-visibleLen(text), 0))
				b.WriteString(" " + text + " " + bar)
			}
			p.printf("%s\n", b.String())
		}
	}

	rule("┌", "┬", "┐")
	line(head, true)
	for _, row := range rows {
		rule("├", "┼", "┤")
		line(row, false)
	}
	rule("└", "┴", "┘")
}

// evidenceLines wraps key=value lines to width, the key grey and the value
// teal, so values stand out from their labels.
func (p *printer) evidenceLines(text string, width int) []string {
	var out []string
	for _, entry := range strings.Split(text, "\n") {
		for j, l := range wrapCell(entry, width) {
			k, v, ok := strings.Cut(l, "=")
			if j > 0 || !ok {
				out = append(out, p.st.fg(cTeal, l))
				continue
			}
			out = append(out, p.st.dim(k+"=")+p.st.fg(cTeal, v))
		}
	}
	return out
}

// wrapCell wraps text into lines of at most width runes. Newlines in text
// start new lines.
func wrapCell(text string, width int) []string {
	var out []string
	for _, para := range strings.Split(text, "\n") {
		line := ""
		for _, word := range strings.Fields(para) {
			for utf8.RuneCountInString(word) > width {
				if line != "" {
					out, line = append(out, line), ""
				}
				r := []rune(word)
				cut := width
				if i := strings.LastIndex(string(r[:width]), "/"); i > 0 {
					cut = utf8.RuneCountInString(string(r[:width])[:i+1])
				}
				out = append(out, string(r[:cut]))
				word = string(r[cut:])
			}
			switch {
			case line == "":
				line = word
			case utf8.RuneCountInString(line)+1+utf8.RuneCountInString(word) <= width:
				line += " " + word
			default:
				out, line = append(out, line), word
			}
		}
		if line != "" || len(out) == 0 {
			out = append(out, line)
		}
	}
	return out
}

// numberRanges writes ascending finding numbers compactly: 1-3, 5.
func numberRanges(ns []int) string {
	var parts []string
	for i := 0; i < len(ns); {
		j := i
		for j+1 < len(ns) && ns[j+1] == ns[j]+1 {
			j++
		}
		if j > i {
			parts = append(parts, fmt.Sprintf("%d-%d", ns[i], ns[j]))
		} else {
			parts = append(parts, strconv.Itoa(ns[i]))
		}
		i = j + 1
	}
	return strings.Join(parts, ", ")
}

func (p *printer) labelled(c color, label, text string) {
	p.wrapped("     "+p.st.fg(c, fmt.Sprintf("%-9s", label))+" ", text, nil)
}

func (p *printer) section(title string) {
	p.printf("\n%s\n", p.st.strong(cMauve, strings.ToUpper(title)))
}

// wrapped prints text after prefix, wrapping at the output width and indenting
// continuation lines to the prefix's visible width. paint, if set, styles
// the text (not the prefix).
func (p *printer) wrapped(prefix, text string, paint func(string) string) {
	p.wrapSegs(prefix, seg{text, paint})
}

// seg is a piece of text with its own style (nil: plain).
type seg struct {
	text  string
	paint func(string) string
}

// wrapSegs prints segments after prefix as one paragraph, wrapping at the
// output width. Each segment keeps its style across line breaks.
func (p *printer) wrapSegs(prefix string, segs ...seg) {
	indent := strings.Repeat(" ", visibleLen(prefix))
	width := max(p.width-visibleLen(prefix), 30)
	// Lines are lists of runs: consecutive words of one segment, painted
	// together so a style is applied once per line, not once per word.
	type run struct {
		seg   int
		words []string
	}
	var lines [][]run
	var cur []run
	n := 0 // visible length of cur
	for si, s := range segs {
		for _, w := range strings.Fields(s.text) {
			wl := utf8.RuneCountInString(w)
			if n > 0 && n+1+wl > width {
				lines, cur, n = append(lines, cur), nil, 0
			}
			if n > 0 {
				n++
			}
			n += wl
			if len(cur) > 0 && cur[len(cur)-1].seg == si {
				cur[len(cur)-1].words = append(cur[len(cur)-1].words, w)
			} else {
				cur = append(cur, run{si, []string{w}})
			}
		}
	}
	if len(cur) > 0 || len(lines) == 0 {
		lines = append(lines, cur)
	}
	for i, l := range lines {
		parts := make([]string, len(l))
		for j, r := range l {
			parts[j] = strings.Join(r.words, " ")
			if paint := segs[r.seg].paint; paint != nil {
				parts[j] = paint(parts[j])
			}
		}
		lead := indent
		if i == 0 {
			lead = prefix
		}
		p.printf("%s%s\n", lead, strings.Join(parts, " "))
	}
}

// visibleLen counts runes outside ANSI escape sequences.
func visibleLen(s string) int {
	n, esc := 0, false
	for _, r := range s {
		switch {
		case r == '\033':
			esc = true
		case esc:
			if r == 'm' {
				esc = false
			}
		default:
			n++
		}
	}
	return n
}

// A cause is a system setting that skips or limits several checks at once.
// COVERAGE names those checks together with how to cover them, instead of
// every line repeating the cause.
type cause struct {
	match   string                                    // in the skip reason or limitation
	explain func(r *report.Report) (string, []string) // heading, how to cover them
}

var causes = []cause{
	{"kptr_restrict", func(r *report.Report) (string, []string) {
		v := -1
		if r.Host.KptrRestrict != nil {
			v = *r.Host.KptrRestrict
		}
		switch v {
		case 2:
			return "kernel.kptr_restrict=2 hides kernel addresses, even from root:", []string{
				"To cover them: sysctl -w kernel.kptr_restrict=1, run Zygarde, then set it back to 2.",
				"If this host isn't meant to set it, a rootkit may have raised it to blind scanners.",
			}
		case 1:
			return "kernel.kptr_restrict=1 hides kernel addresses from processes without CAP_SYSLOG:",
				[]string{"To cover them, run Zygarde as root with CAP_SYSLOG."}
		}
		return "Kernel addresses were hidden:", nil
	}},
	{"lockdown (confidentiality)", func(*report.Report) (string, []string) {
		return "Kernel lockdown (confidentiality) blocks reading kernel memory:",
			[]string{"Lockdown can't be lowered at runtime: boot without lockdown=confidentiality to cover them."}
	}},
}

// causeOf returns the index in causes of what a skip reason or limitation
// comes from, or -1.
func causeOf(s string) int {
	return slices.IndexFunc(causes, func(c cause) bool { return strings.Contains(s, c.match) })
}

func (p *printer) causeCoverage(r *report.Report, c cause, skipped, partial []string) {
	if len(skipped)+len(partial) == 0 {
		return
	}
	heading, fix := c.explain(r)
	p.wrapped("  ", heading, func(s string) string { return p.st.fg(cYellow, s) })
	if len(skipped) > 0 {
		p.wrapped("    "+p.st.dim("-")+" Not checked: ", strings.Join(skipped, ", "), p.st.bold)
	}
	if len(partial) > 0 {
		p.wrapped("    "+p.st.dim("-")+" Partly checked (*): ", strings.Join(partial, ", "), p.st.bold)
	}
	for _, f := range fix {
		p.wrapped("    ", f, nil)
	}
}

func (p *printer) writeJSON(r *report.Report) {
	enc := json.NewEncoder(p.w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(r)
}

// errOutputExists means the -o path already exists. Zygarde runs as root and
// never replaces a file: a mistyped -o could otherwise clobber a system file,
// and a device or pipe (-o /dev/null) would be replaced by a regular file.
var errOutputExists = errors.New("it already exists (zygarde never overwrites a file; choose a new path)")

// checkOutputWritable verifies before the scan that path does not exist and
// that its parent directory exists and is writable, avoiding lost reports
// after long runs.
func checkOutputWritable(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return errOutputExists
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".zygarde-out-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}

// saveReport writes the JSON report to a new file at path, readable by the
// owner only. The report is written to a temporary file and hard-linked to
// path, which fails if anything exists there: the report appears complete or
// not at all, and nothing is ever replaced. Filesystems without hard links get
// an exclusive create instead.
func saveReport(r *report.Report, path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".zygarde-report-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	defer os.Remove(tmpName)
	err = os.Link(tmpName, path)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, fs.ErrExist):
		return fmt.Errorf("%s: %w", path, errOutputExists)
	case errors.Is(err, syscall.EPERM), errors.Is(err, syscall.ENOTSUP), errors.Is(err, syscall.EOPNOTSUPP), errors.Is(err, syscall.EMLINK):
		return writeNew(path, data) // no hard links here (FAT, some FUSE filesystems)
	}
	return err
}

// writeNew creates path, which must not exist (O_EXCL, and O_NOFOLLOW so a
// symlink planted there is not followed), and writes data to it.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s: %w", path, errOutputExists)
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}
