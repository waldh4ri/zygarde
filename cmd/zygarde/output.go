package main

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/waldh4ri/zygarde/internal/core"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorGray   = "\033[90m"
)

const banner = `
 ███████╗██╗   ██╗ ██████╗  █████╗ ██████╗ ██████╗ ███████╗
 ╚══███╔╝╚██╗ ██╔╝██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██╔════╝
   ███╔╝  ╚████╔╝ ██║  ███╗███████║██████╔╝██║  ██║█████╗
  ███╔╝    ╚██╔╝  ██║   ██║██╔══██║██╔══██╗██║  ██║██╔══╝
 ███████╗   ██║   ╚██████╔╝██║  ██║██║  ██║██████╔╝███████╗
 ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝

 Guardian of the Kernel - eBPF Rootkit Detection
 Version ` + version + `
`

// printer renders progress and results as text, or only JSON at the end.
type printer struct {
	w     io.Writer
	json  bool
	index int
	total int
}

func newPrinter(w io.Writer, jsonMode bool) *printer { return &printer{w: w, json: jsonMode} }

func (p *printer) fatal(msg string) int {
	if p.json {
		r := core.Result{Cell: "system", Name: "System", Error: msg}
		r.SetStatus(core.StatusError)
		p.writeJSON([]core.Result{r})
	} else {
		fmt.Fprintf(p.w, "%s[-]%s %s\n", colorRed, colorReset, msg)
	}
	return 1
}

func (p *printer) header(n int) {
	p.total = n
	if p.json {
		return
	}
	fmt.Fprint(p.w, banner+"\n")
	fmt.Fprintf(p.w, "Deploying %d Zygarde Cells...\n\n", n)
}

func (p *printer) start(c core.Cell) {
	p.index++
	if p.json {
		return
	}
	fmt.Fprintf(p.w, "[Cell %d/%d] %s\n", p.index, p.total, c.Name())
	fmt.Fprintf(p.w, "            %s%s%s\n", colorGray, c.Description(), colorReset)
}

func (p *printer) result(r core.Result) {
	if p.json {
		return
	}
	sym, color := symbol(r.Status)
	msg := r.Message
	if msg == "" {
		msg = r.StatusText
	}
	fmt.Fprintf(p.w, "            %s%s%s %s (%.2fs)\n", color, sym, colorReset, msg, r.DurationSeconds)
	if r.Error != "" && r.Status != core.StatusSkipped {
		fmt.Fprintf(p.w, "              %s[-]%s %s\n", colorRed, colorReset, r.Error)
	}
	for _, f := range r.Findings {
		fmt.Fprintf(p.w, "              %s[*]%s %s\n", colorYellow, colorReset, f.Description)
		for _, k := range slices.Sorted(maps.Keys(f.Details)) {
			fmt.Fprintf(p.w, "                  - %s: %s\n", k, f.Details[k])
		}
	}
	const maxObservations = 15
	for i, o := range r.Observations {
		if i == maxObservations {
			fmt.Fprintf(p.w, "              %s[i] ... %d more (see --json)%s\n", colorGray, len(r.Observations)-i, colorReset)
			break
		}
		fmt.Fprintf(p.w, "              %s[i] %s%s\n", colorGray, o.Description, colorReset)
	}
	fmt.Fprintln(p.w)
}

func (p *printer) summary(results []core.Result) {
	if p.json {
		p.writeJSON(results)
		return
	}
	counts := map[core.Status]int{}
	for _, r := range results {
		counts[r.Status]++
	}
	line := strings.Repeat("=", 70)
	fmt.Fprintln(p.w, line)
	fmt.Fprintln(p.w, "ZYGARDE CORE ANALYSIS - SUMMARY")
	fmt.Fprintln(p.w, line)
	fmt.Fprintf(p.w, "  %s[+]%s OK:         %d\n", colorGreen, colorReset, counts[core.StatusOK])
	fmt.Fprintf(p.w, "  %s[*]%s SUSPICIOUS: %d\n", colorYellow, colorReset, counts[core.StatusSuspicious])
	fmt.Fprintf(p.w, "  %s[-]%s ERROR:      %d\n", colorRed, colorReset, counts[core.StatusError])
	fmt.Fprintf(p.w, "  %s[~]%s SKIPPED:    %d\n", colorGray, colorReset, counts[core.StatusSkipped])
	fmt.Fprintln(p.w, line)
	switch core.ExitCode(results) {
	case 2:
		fmt.Fprintf(p.w, "%s[*] ECOSYSTEM THREAT DETECTED%s\n", colorRed, colorReset)
	case 1:
		fmt.Fprintf(p.w, "%s[-] Some Cells could not complete their analysis%s\n", colorYellow, colorReset)
	default:
		fmt.Fprintf(p.w, "%s[+] Ecosystem stable - no threats detected%s\n", colorGreen, colorReset)
	}
	fmt.Fprintln(p.w, "    A clean result raises the bar; it cannot prove a kernel-level compromise absent.")
	fmt.Fprintln(p.w, line)
}

func (p *printer) writeJSON(results []core.Result) {
	enc := json.NewEncoder(p.w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(results)
}

func symbol(s core.Status) (string, string) {
	switch s {
	case core.StatusOK:
		return "[+]", colorGreen
	case core.StatusSuspicious:
		return "[*]", colorYellow
	case core.StatusError:
		return "[-]", colorRed
	case core.StatusSkipped:
		return "[~]", colorGray
	default:
		return "[?]", colorReset
	}
}
