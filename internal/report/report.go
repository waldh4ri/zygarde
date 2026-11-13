// Package report holds a scan's results together with the context needed to
// interpret them later: which host, which kernel, when, and with what tool.
package report

import (
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fsutil"
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
	Hostname      string `json:"hostname"`
	MachineID     string `json:"machine_id,omitempty"`
	Distro        string `json:"distro"`
	Kernel        string `json:"kernel"`
	KernelVersion string `json:"kernel_version,omitempty"`
	Arch          string `json:"arch"`
	Lockdown      string `json:"lockdown"`
	KptrRestrict  *int   `json:"kptr_restrict,omitempty"` // kernel.kptr_restrict, when readable
	BTF           bool   `json:"btf"`
	BootID        string `json:"boot_id,omitempty"`
	BootTime      string `json:"boot_time,omitempty"`
}

// ScannerFootprint records Zygarde's own execution context and transient
// objects created during the scan so DFIR analysts can filter scanner noise
// out of auditd, EDR and filesystem timelines.
type ScannerFootprint struct {
	PID          int                  `json:"pid"`
	WorkerPIDs   []int                `json:"worker_pids,omitempty"`
	BinarySHA256 string               `json:"binary_sha256,omitempty"`
	Args         []string             `json:"args,omitempty"`
	Artifacts    []core.FootprintItem `json:"artifacts,omitempty"`
}

// Report is the full outcome of a scan. It is what --json prints and what
// --output saves.
type Report struct {
	Tool             string            `json:"tool"`
	Version          string            `json:"version"`
	Host             Host              `json:"host"`
	ScannerFootprint *ScannerFootprint `json:"scanner_footprint,omitempty"`
	StartedAt        time.Time         `json:"started_at"`
	FinishedAt       time.Time         `json:"finished_at"`
	Verdict          Verdict           `json:"verdict"`
	Findings         int               `json:"findings"`
	Results          []core.Result     `json:"results"`
}

// New starts a report for this host.
func New(version string, args []string) *Report {
	binSum, _ := fsutil.SHA256File("/proc/self/exe")
	return &Report{
		Tool:    "zygarde",
		Version: version,
		Host:    probeHost(),
		ScannerFootprint: &ScannerFootprint{
			PID:          os.Getpid(),
			BinarySHA256: binSum,
			Args:         args,
		},
		StartedAt: time.Now().UTC(),
	}
}

// AddWorkerPIDs records supervised worker PIDs in the scanner footprint.
func (r *Report) AddWorkerPIDs(pids []int) {
	if r.ScannerFootprint != nil && len(pids) > 0 {
		r.ScannerFootprint.WorkerPIDs = append(r.ScannerFootprint.WorkerPIDs, pids...)
	}
}

// Finish records the results and computes the verdict.
func (r *Report) Finish(results []core.Result) {
	r.FinishedAt = time.Now().UTC()
	r.Results = results
	r.Findings = 0
	for _, res := range results {
		r.Findings += len(res.Findings)
		if r.ScannerFootprint != nil && len(res.Footprint) > 0 {
			r.ScannerFootprint.Artifacts = append(r.ScannerFootprint.Artifacts, res.Footprint...)
		}
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
		Kernel:        kernel.Release(),
		KernelVersion: kernel.Version(),
		Arch:          runtime.GOARCH,
		Lockdown:      kernel.Lockdown(),
		Distro:        distro(),
	}
	h.Hostname, _ = os.Hostname()
	if v := kernel.KptrRestrict(); v >= 0 {
		h.KptrRestrict = &v
	}
	if h.Lockdown == "" {
		h.Lockdown = "unavailable"
	}
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	h.BTF = err == nil
	if b, err := fsutil.ReadFileNoAtime("/proc/sys/kernel/random/boot_id"); err == nil {
		h.BootID = strings.TrimSpace(string(b))
	}
	if b, err := fsutil.ReadFileNoAtime("/etc/machine-id"); err == nil {
		h.MachineID = strings.TrimSpace(string(b))
	}
	if bt := kernel.BootTime(); !bt.IsZero() {
		h.BootTime = bt.Format(time.RFC3339)
	}
	return h
}

// distro returns PRETTY_NAME from os-release.
func distro() string {
	for _, path := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		data, err := fsutil.ReadFileNoAtime(path)
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
