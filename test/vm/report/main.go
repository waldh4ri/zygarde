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
		if err := json.Unmarshal(data, &t.results); err != nil {
			t.err = "bad results.json: " + err.Error()
		}
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
			switch r.Status {
			case core.StatusSkipped:
				skips = append(skips, fmt.Sprintf("%s / %s: %s", t.name(), c, r.Message))
			case core.StatusError, core.StatusSuspicious:
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
