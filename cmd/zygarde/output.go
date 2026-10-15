package main

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/report"
)

// termWidth is the output width: the terminal's, or 100 when not a terminal.
func termWidth(f *os.File) int {
	if ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ); err == nil && ws.Col >= 60 {
		return int(ws.Col)
	}
	return 100
}

// style applies ANSI colors when enabled.
type style struct{ on bool }

func (s style) wrap(code, text string) string {
	if !s.on {
		return text
	}
	return "\033[" + code + "m" + text + "\033[0m"
}
func (s style) bold(t string) string   { return s.wrap("1", t) }
func (s style) dim(t string) string    { return s.wrap("2", t) }
func (s style) red(t string) string    { return s.wrap("1;31", t) }
func (s style) yellow(t string) string { return s.wrap("1;33", t) }
func (s style) green(t string) string  { return s.wrap("32", t) }

// colorEnabled follows the usual conventions: only on a terminal, never with
// NO_COLOR set (https://no-color.org) or --no-color.
func colorEnabled(f *os.File, flagOff bool) bool {
	if flagOff || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

// printer renders a scan for a person at a terminal, or only JSON at the end.
type printer struct {
	w       io.Writer
	json    bool
	verbose bool
	st      style
	index   int
	total   int
	nameW   int
	width   int
}

func newPrinter(w io.Writer, jsonMode, verbose, color bool, width int) *printer {
	return &printer{w: w, json: jsonMode, verbose: verbose, st: style{on: color}, width: width}
}

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
	if p.json {
		return
	}
	h := r.Host
	btf := "no"
	if h.BTF {
		btf = "yes"
	}
	p.printf("%s %s\n\n", p.st.bold("zygarde "+version), p.st.dim("· eBPF rootkit triage for Linux"))
	p.printf("  %-9s %s\n", "Host", h.Hostname)
	p.printf("  %-9s %s · Linux %s · %s\n", "System", h.Distro, h.Kernel, h.Arch)
	p.printf("  %-9s BTF %s · lockdown %s\n", "Kernel", btf, h.Lockdown)
	p.printf("  %-9s %s\n\n", "Started", r.StartedAt.Format("2006-01-02 15:04:05 MST"))
}

func (p *printer) start(c core.Cell) {
	p.index++
	if p.json {
		return
	}
	if p.verbose {
		p.printf("  %s\n", p.st.dim(fmt.Sprintf("[%d/%d] %s: %s", p.index, p.total, c.Name(), c.Description())))
	}
}

// result prints one aligned line per Cell: status, then its summary.
func (p *printer) result(r core.Result) {
	if p.json {
		return
	}
	label := fmt.Sprintf("[%d/%d] %-*s", p.index, p.total, p.nameW, r.Name)
	text := r.StatusText
	if r.Status == core.StatusOK && len(r.Limitations) > 0 {
		text += "*" // partly checked; listed under Coverage
	}
	status := fmt.Sprintf("%-10s", text)
	summary := r.Message
	switch r.Status {
	case core.StatusOK:
		status = p.st.green(status)
	case core.StatusSkipped:
		status = p.st.dim(status)
	case core.StatusError:
		status = p.st.red(status)
		summary = r.Error
	case core.StatusSuspicious:
		status = p.st.yellow(status)
		summary = fmt.Sprintf("%d finding(s), see below", len(r.Findings))
	}
	if r.Status != core.StatusSkipped {
		summary += fmt.Sprintf(" (%.1fs)", r.DurationSeconds)
	}
	var paint func(string) string
	if r.Status == core.StatusSkipped {
		paint = p.st.dim
	}
	prefix := fmt.Sprintf("  %s  %s ", label, status)
	if visibleLen(prefix)+utf8.RuneCountInString(summary) <= p.width {
		p.wrapped(prefix, summary, paint)
	} else {
		// Too long to sit beside the status: give it its own lines.
		p.printf("%s\n", strings.TrimRight(prefix, " "))
		p.wrapped("        ", summary, paint)
	}

	if p.verbose {
		for _, o := range r.Observations {
			p.printf("        %s\n", p.st.dim("· "+o.Description))
		}
		for _, c := range r.Canaries {
			mark := "seen"
			if !c.Observed {
				mark = "MISSING"
			}
			p.printf("        %s\n", p.st.dim(fmt.Sprintf("canary %s in %s: %s", c.Canary, c.View, mark)))
		}
	}
}

// summary prints findings, coverage, the verdict and what to do next.
func (p *printer) summary(r *report.Report, savedTo string) {
	if p.json {
		p.writeJSON(r)
		return
	}

	if r.Findings > 0 {
		p.section("Findings")
		n := 0
		for _, res := range r.Results {
			for _, f := range res.Findings {
				n++
				p.finding(n, res.Name, f)
			}
		}
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
	if len(errs) > 0 {
		p.section("Errors")
		for _, res := range errs {
			p.printf("  %s: %s\n", p.st.bold(res.Name), res.Error)
		}
	}

	p.section("Coverage")
	p.printf("  %d of %d checks completed.\n", completed, len(r.Results))
	if len(skipped) > 0 {
		p.printf("  Not checked on this system:\n")
		for _, res := range skipped {
			p.wrapped("    - ", res.Name+": "+res.Message, nil)
		}
	}
	partial := false
	for _, res := range r.Results {
		for _, l := range res.Limitations {
			if !partial {
				p.printf("  Partly checked (*):\n")
				partial = true
			}
			p.wrapped("    - ", res.Name+": "+l, nil)
		}
	}

	p.section("Verdict")
	switch r.Verdict {
	case report.VerdictSuspicious:
		cells := 0
		for _, res := range r.Results {
			if len(res.Findings) > 0 {
				cells++
			}
		}
		p.printf("  %s  %d finding(s) in %d check(s). Exit code 2.\n", p.st.red("SUSPICIOUS"), r.Findings, cells)
	case report.VerdictIncomplete:
		p.printf("  %s  no findings, but %d check(s) failed. Exit code 1.\n", p.st.yellow("INCOMPLETE"), len(errs))
	default:
		p.printf("  %s  no signs of hiding or tampering in the checks that ran. Exit code 0.\n", p.st.green("CLEAN"))
	}

	p.section("Next steps")
	for i, step := range nextSteps(r.Verdict) {
		p.wrapped(fmt.Sprintf("  %d. ", i+1), step, nil)
	}
	if savedTo != "" {
		p.printf("\n  Report saved to %s\n", savedTo)
	}
}

func (p *printer) finding(n int, cell string, f core.Finding) {
	p.printf("\n  %s %s\n", p.st.yellow(fmt.Sprintf("%d.", n)), p.st.bold(cell))
	p.wrapped("     ", f.Description, nil)
	if len(f.Details) > 0 {
		var ev []string
		for _, k := range slices.Sorted(maps.Keys(f.Details)) {
			ev = append(ev, k+"="+f.Details[k])
		}
		p.labelled("Evidence", strings.Join(ev, " · "))
	}
	if f.Why != "" {
		p.labelled("Why", f.Why)
	}
	if f.Benign != "" {
		p.labelled("Rule out", f.Benign)
	}
}

func (p *printer) labelled(label, text string) {
	p.wrapped("     "+p.st.dim(fmt.Sprintf("%-9s", label))+" ", text, nil)
}

func (p *printer) section(title string) {
	p.printf("\n%s\n", p.st.bold(strings.ToUpper(title)))
}

// wrapped prints text after prefix, wrapping at the output width and indenting
// continuation lines to the prefix's visible width. paint, if set, styles
// the text (not the prefix).
func (p *printer) wrapped(prefix, text string, paint func(string) string) {
	if paint == nil {
		paint = func(s string) string { return s }
	}
	indent := strings.Repeat(" ", visibleLen(prefix))
	width := max(p.width-visibleLen(prefix), 30)
	line := ""
	first := true
	flush := func() {
		if first {
			p.printf("%s%s\n", prefix, paint(line))
			first = false
		} else {
			p.printf("%s%s\n", indent, paint(line))
		}
		line = ""
	}
	for _, word := range strings.Fields(text) {
		if line != "" && utf8.RuneCountInString(line)+1+utf8.RuneCountInString(word) > width {
			flush()
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	if line != "" || first {
		flush()
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

func nextSteps(v report.Verdict) []string {
	switch v {
	case report.VerdictSuspicious:
		return []string{
			"Keep the system running. Don't reboot, unload modules or kill processes yet: memory-resident evidence and the kernel's taint state would be lost.",
			"Preserve evidence first: save this report (--output) and capture memory, e.g. with AVML or LiME.",
			"Analyse the memory image offline, e.g. with Volatility 3, and check each finding against its \"Rule out\" notes.",
			"Until the findings are explained, treat credentials and keys used on this host as exposed.",
		}
	case report.VerdictIncomplete:
		return []string{
			"Some checks could not finish (see Errors). Re-run with -d to see why.",
			"Results from the checks that completed stand; the failed ones give no assurance either way.",
		}
	default:
		return []string{
			"Nothing to act on from this scan. A clean result raises the bar for an attacker but can't prove that a kernel-level compromise is absent.",
			"If you have other reasons for suspicion, capture memory for offline analysis.",
		}
	}
}

func (p *printer) writeJSON(r *report.Report) {
	enc := json.NewEncoder(p.w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(r)
}

// saveReport writes the JSON report to path, readable by the owner only.
func saveReport(r *report.Report, path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}
