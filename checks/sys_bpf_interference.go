package checks

import (
	"time"
)

// SysBpfInterferenceCheck is a stub Cell intended to detect attempts to hide
// eBPF programs/maps/links by manipulating sys_bpf return values (e.g. via
// bpf_override_return to force -ENOENT on NEXT_ID enumeration).
//
// Planned implementation outline:
//  1. Attach tracepoint sys_enter_bpf and kretprobe sys_bpf.
//  2. Record sequence of BPF commands (PROG_NEXT_ID, MAP_NEXT_ID, LINK_NEXT_ID) per pid.
//  3. Correlate kretprobe return values with expected kernel object graph built
//     from bpffs pins and link introspection.
//  4. Flag patterns where enumeration prematurely ends while referenced FDs / pinned paths exist.
//  5. Provide findings with: pid, command, suppressed next_id, pinned path(s) referencing hidden ID.
//
// For now this is a non-functional placeholder returning OK. It can be safely
// added to the execution list; it imposes no kernel instrumentation yet.
type SysBpfInterferenceCheck struct {
	debug bool
}

// NewSysBpfInterferenceCheck creates the stub instance.
func NewSysBpfInterferenceCheck() *SysBpfInterferenceCheck {
	return &SysBpfInterferenceCheck{}
}

// SetDebug toggles debug output (reserved for future implementation).
func (c *SysBpfInterferenceCheck) SetDebug(d bool) { c.debug = d }

// Name returns the Cell name.
func (c *SysBpfInterferenceCheck) Name() string { return "sys_bpf Interference" }

// Description explains the purpose of the Cell.
func (c *SysBpfInterferenceCheck) Description() string {
	return "Detects hiding of BPF programs/maps/links by monitoring sys_bpf enumeration anomalies (stub)"
}

// Run executes the stub logic (no kernel activity yet).
func (c *SysBpfInterferenceCheck) Run() (Result, error) {
	start := time.Now()
	r := Result{
		Status:   StatusOK,
		Findings: []Finding{},
		Message:  "Stub: sys_bpf interference detection not implemented yet",
		Duration: 0,
	}
	r.Duration = time.Since(start)
	return r, nil
}

// Cleanup performs teardown (nothing for stub).
func (c *SysBpfInterferenceCheck) Cleanup() error { return nil }
