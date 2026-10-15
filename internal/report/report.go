// Package report holds a scan's results together with the context needed to
// interpret them later: which host, which kernel, when, and with what tool.
package report

import (
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/kernel"
)

// Verdict summarizes a scan.
type Verdict string

const (
	VerdictClean      Verdict = "clean"
	VerdictSuspicious Verdict = "suspicious"
	VerdictIncomplete Verdict = "incomplete" // no findings, but some Cells failed
)

// Host describes the scanned system.
type Host struct {
	Hostname string `json:"hostname"`
	Distro   string `json:"distro"`
	Kernel   string `json:"kernel"`
	Arch     string `json:"arch"`
	Lockdown string `json:"lockdown"`
	BTF      bool   `json:"btf"`
	BootID   string `json:"boot_id,omitempty"`
}

// Report is the full outcome of a scan. It is what --json prints and what
// --output saves.
type Report struct {
	Tool       string        `json:"tool"`
	Version    string        `json:"version"`
	Host       Host          `json:"host"`
	StartedAt  time.Time     `json:"started_at"`
	FinishedAt time.Time     `json:"finished_at"`
	Verdict    Verdict       `json:"verdict"`
	Findings   int           `json:"findings"`
	Results    []core.Result `json:"results"`
}

// New starts a report for this host.
func New(version string) *Report {
	return &Report{
		Tool:      "zygarde",
		Version:   version,
		Host:      probeHost(),
		StartedAt: time.Now().UTC(),
	}
}

// Finish records the results and computes the verdict.
func (r *Report) Finish(results []core.Result) {
	r.FinishedAt = time.Now().UTC()
	r.Results = results
	r.Findings = 0
	for _, res := range results {
		r.Findings += len(res.Findings)
	}
	switch core.ExitCode(results) {
	case 2:
		r.Verdict = VerdictSuspicious
	case 1:
		r.Verdict = VerdictIncomplete
	default:
		r.Verdict = VerdictClean
	}
}

// ExitCode is the process exit code for the report.
func (r *Report) ExitCode() int { return core.ExitCode(r.Results) }

func probeHost() Host {
	h := Host{
		Kernel:   kernel.Release(),
		Arch:     runtime.GOARCH,
		Lockdown: kernel.Lockdown(),
		Distro:   distro(),
	}
	h.Hostname, _ = os.Hostname()
	if h.Lockdown == "" {
		h.Lockdown = "unavailable"
	}
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	h.BTF = err == nil
	if b, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		h.BootID = strings.TrimSpace(string(b))
	}
	return h
}

// distro returns PRETTY_NAME from os-release.
func distro() string {
	for _, path := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
				return strings.Trim(v, `"'`)
			}
		}
	}
	return "unknown"
}
