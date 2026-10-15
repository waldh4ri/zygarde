package core

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Cell is one detection module.
//
// A Cell must release every kernel resource it acquires (programs, maps,
// links, canaries) before Run returns.
type Cell interface {
	// ID is a stable machine-readable identifier, e.g. "hidden_process".
	ID() string
	// Name is a short human-readable name.
	Name() string
	// Description explains what the Cell looks for.
	Description() string
	// Timeout bounds Run. The supervisor kills the worker if it is exceeded.
	Timeout() time.Duration
	// Supported returns nil if the Cell can run on this system, or an error
	// created with Skip explaining why it doesn't apply.
	Supported(env *Env) error
	// Run performs the analysis and records observations on rec.
	Run(ctx context.Context, env *Env, rec *Recorder) error
}

// SkipError marks a Cell as not applicable to this system.
type SkipError struct {
	Reason string
}

func (e *SkipError) Error() string { return e.Reason }

// Skip returns a SkipError with a formatted reason.
func Skip(format string, args ...any) error {
	return &SkipError{Reason: fmt.Sprintf(format, args...)}
}

// BPFError wraps a failed bpf() operation (load, attach, enumerate...).
// The runner uses it to tell kernel incompatibility apart from interference.
type BPFError struct {
	Op  string
	Err error
}

func (e *BPFError) Error() string { return e.Op + ": " + e.Err.Error() }
func (e *BPFError) Unwrap() error { return e.Err }

// WrapBPF wraps err as a BPFError for operation op. It returns nil if err is nil.
func WrapBPF(op string, err error) error {
	if err == nil {
		return nil
	}
	var be *BPFError
	if errors.As(err, &be) {
		return err
	}
	return &BPFError{Op: op, Err: err}
}

// Recorder collects a Cell's observations while it runs.
type Recorder struct {
	log      *slog.Logger
	message  string
	findings []Finding
	observed []Finding
	canaries []CanaryCheck
	limits   []string
}

// NewRecorder returns an empty Recorder; the runner creates one per Cell.
func NewRecorder(log *slog.Logger) *Recorder {
	return &Recorder{log: log}
}

// Findings returns the findings recorded so far.
func (r *Recorder) Findings() []Finding { return r.findings }

// Log returns the Cell's logger.
func (r *Recorder) Log() *slog.Logger { return r.log }

// Suspicious records a finding. Fill in Why and Benign: the person reading
// the report needs to know why it matters and what else could explain it.
func (r *Recorder) Suspicious(f Finding) {
	r.log.Debug("finding", "description", f.Description)
	r.findings = append(r.findings, f)
}

// Observe records context that is worth reporting but not suspicious by
// itself, such as an inventory of legitimate hooks.
func (r *Recorder) Observe(description string, details map[string]string) {
	r.observed = append(r.observed, Finding{Description: description, Details: details})
}

// Limit records part of the check that could not run here, so the report
// doesn't claim more coverage than it has.
func (r *Recorder) Limit(format string, args ...any) {
	r.limits = append(r.limits, fmt.Sprintf(format, args...))
}

// Canary records whether a planted object was observed in a view.
func (r *Recorder) Canary(canary, view string, observed bool) {
	r.log.Debug("canary", "canary", canary, "view", view, "observed", observed)
	r.canaries = append(r.canaries, CanaryCheck{Canary: canary, View: view, Observed: observed})
}

// Message sets the summary line shown for the Cell.
func (r *Recorder) Message(format string, args ...any) {
	r.message = fmt.Sprintf(format, args...)
}
