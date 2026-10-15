package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/waldh4ri/zygarde/internal/core"
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
	var buf bytes.Buffer
	p := newPrinter(&buf, false, false, false, 100)
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
		Details:     map[string]string{"path": "/usr/lib/.cache", "directory": "/usr/lib"},
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
		"FINDINGS", "/usr/lib/.cache exists", "Evidence", "directory=/usr/lib · path=/usr/lib/.cache", "Why", "Rule out",
		"OK*", "Partly checked (*)", "Not checked on this system",
		"Exit code 2", "Keep the system running", "Report saved to report.json",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	if strings.Contains(out, "\033[") {
		t.Error("colors must be off when disabled")
	}
}

func TestRenderClean(t *testing.T) {
	out := render(t, []core.Result{result("kernel_taint", "Kernel Taint Consistency", core.StatusOK, "Kernel is not tainted")})
	for _, want := range []string{"CLEAN", "Exit code 0", "can't prove"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	if strings.Contains(out, "FINDINGS") {
		t.Error("clean report must not have a findings section")
	}
}

func TestWrapped(t *testing.T) {
	var buf bytes.Buffer
	p := newPrinter(&buf, false, false, false, 40)
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
