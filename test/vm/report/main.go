// Command report summarizes VM test results as a Markdown matrix and fails if
// any target has an ERROR, a SUSPICIOUS result or a missed canary. On a clean
// test VM, every Cell must be OK or SKIPPED.
//
// usage: go run ./test/vm/report test/vm/out
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/report"
)

type target struct {
	dir     string
	meta    map[string]string
	results []core.Result
	err     string // why the target itself failed
}

func load(dir string) target {
	t := target{dir: dir, meta: map[string]string{}}
	if f, err := os.Open(filepath.Join(dir, "meta.env")); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if k, v, ok := strings.Cut(sc.Text(), "="); ok {
				t.meta[k] = v
			}
		}
		f.Close()
	}
	data, err := os.ReadFile(filepath.Join(dir, "results.json"))
	switch {
	case t.meta["boot_error"] != "":
		t.err = t.meta["boot_error"]
	case err != nil:
		t.err = "no results: " + err.Error()
	default:
		var rep report.Report
		if err := json.Unmarshal(data, &rep); err != nil {
			t.err = "bad results.json: " + err.Error()
		}
		t.results = rep.Results
	}
	if t.err == "" && t.meta["lockdown_error"] != "" {
		t.err = t.meta["lockdown_error"]
	}
	return t
}

func (t target) name() string {
	if n := t.meta["target"]; n != "" {
		return n
	}
	return filepath.Base(t.dir)
}

var symbols = map[core.Status]string{
	core.StatusOK:         "✅ OK",
	core.StatusSkipped:    "⏭️ SKIP",
	core.StatusError:      "❌ ERROR",
	core.StatusSuspicious: "🚨 SUSP",
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: report <results-dir>")
		os.Exit(2)
	}
	entries, err := os.ReadDir(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	expects, err := loadExpectations(filepath.Join(filepath.Dir(os.Args[1]), "fixtures.expect"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var targets []target
	var cells []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		t := load(filepath.Join(os.Args[1], e.Name()))
		for _, r := range t.results {
			if !slices.Contains(cells, r.Cell) {
				cells = append(cells, r.Cell)
			}
		}
		targets = append(targets, t)
	}

	fmt.Printf("| Target | Kernel | Distro | BTF | Lockdown | %s |\n", strings.Join(cells, " | "))
	fmt.Printf("|---|---|---|---|---|%s\n", strings.Repeat("---|", len(cells)))
	var problems, skips []string
	for _, t := range targets {
		row := []string{t.name(), t.meta["kernel"], t.meta["distro"], t.meta["btf"], t.meta["lockdown"]}
		byCell := map[string]core.Result{}
		for _, r := range t.results {
			byCell[r.Cell] = r
		}
		for _, c := range cells {
			r, ok := byCell[c]
			if !ok {
				row = append(row, "—")
				continue
			}
			row = append(row, symbols[r.Status])
			switch {
			case r.Status == core.StatusSkipped:
				skips = append(skips, fmt.Sprintf("%s / %s: %s", t.name(), c, r.Message))
			case r.Status == core.StatusSuspicious && t.fixtures() && expectsFindings(expects, c):
				// Expected: checked against fixtures.expect below.
			case r.Status == core.StatusError || r.Status == core.StatusSuspicious:
				detail := r.Error
				for _, f := range r.Findings {
					detail += "; " + f.Description
				}
				problems = append(problems, fmt.Sprintf("%s / %s: %s %s", t.name(), c, r.StatusText, strings.TrimPrefix(detail, "; ")))
			}
			for _, cc := range r.Canaries {
				if !cc.Observed {
					problems = append(problems, fmt.Sprintf("%s / %s: canary %s missing from %s", t.name(), c, cc.Canary, cc.View))
				}
			}
		}
		if t.err != "" {
			problems = append(problems, fmt.Sprintf("%s: %s", t.name(), t.err))
		}
		if t.fixtures() && t.err == "" {
			for _, e := range expects {
				if !e.met(byCell[e.cell]) {
					problems = append(problems, fmt.Sprintf("%s / %s: expected %s not reported: %s", t.name(), e.cell, e.kind, e.line))
				}
			}
		}
		fmt.Printf("| %s |\n", strings.Join(row, " | "))
	}

	if len(skips) > 0 {
		fmt.Println("\n**Skipped**")
		for _, s := range skips {
			fmt.Println("- " + s)
		}
	}
	if len(problems) > 0 {
		fmt.Println("\n**Problems**")
		for _, p := range problems {
			fmt.Println("- " + p)
		}
		os.Exit(1)
	}
	fmt.Printf("\nAll %d targets clean.\n", len(targets))
}

// fixtures reports whether stand-ins were planted on this target.
func (t target) fixtures() bool { return t.meta["fixtures"] == "yes" }

// expectation is one line of fixtures.expect.
type expectation struct {
	cell, kind, desc string
	key, value       string // optional detail that must contain value
	line             string
}

func loadExpectations(path string) ([]expectation, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading expectations: %w", err)
	}
	defer f.Close()
	var out []expectation
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 3 || (parts[1] != "finding" && parts[1] != "observation") {
			return nil, fmt.Errorf("%s: bad line %q", path, line)
		}
		e := expectation{cell: parts[0], kind: parts[1], desc: parts[2], line: line}
		if len(parts) > 3 {
			e.key, e.value, _ = strings.Cut(parts[3], "=")
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

func expectsFindings(expects []expectation, cell string) bool {
	for _, e := range expects {
		if e.cell == cell && e.kind == "finding" {
			return true
		}
	}
	return false
}

// met reports whether a Cell's result contains the expected entry.
func (e expectation) met(r core.Result) bool {
	list := r.Observations
	if e.kind == "finding" {
		list = r.Findings
	}
	for _, f := range list {
		if strings.Contains(f.Description, e.desc) && (e.key == "" || strings.Contains(f.Details[e.key], e.value)) {
			return true
		}
	}
	return false
}
