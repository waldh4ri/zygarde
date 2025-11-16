package checks

import (
	"encoding/json"
	"time"
)

// Status represents the result status of a forensic check
type Status int

const (
	// StatusOK indicates the check passed without issues (0)
	StatusOK Status = 0
	// StatusError indicates the check encountered an error (1)
	StatusError Status = 1
	// StatusSuspicious indicates potential rootkit activity detected (2)
	StatusSuspicious Status = 2
)

// String returns the string representation of the status
func (s Status) String() string {
	switch s {
	case StatusOK:
		return "OK"
	case StatusError:
		return "ERROR"
	case StatusSuspicious:
		return "SUSPICIOUS"
	default:
		return "UNKNOWN"
	}
}

// MarshalJSON implements json.Marshaler for Status
func (s Status) MarshalJSON() ([]byte, error) {
	return json.Marshal(int(s))
}

// Finding represents a single suspicious discovery
type Finding struct {
	// Description of what was found
	Description string `json:"description"`
	// Details provides additional context
	Details map[string]string `json:"details"`
}

// Result represents the outcome of running a check
type Result struct {
	// Cell is the name of the check that produced this result
	Cell string `json:"cell"`
	// Status is the overall status of the check (0=OK, 1=Error, 2=Suspicious)
	Status Status `json:"status"`
	// Message provides a summary of the check result
	Message string `json:"message,omitempty"`
	// Suspicious contains detailed suspicious items found
	Suspicious []Finding `json:"suspicious,omitempty"`
	// Duration is how long the check took to run (in seconds)
	DurationSeconds float64 `json:"duration_seconds"`
	// ErrorMessage contains the error message if an error occurred
	ErrorMessage string `json:"error_message,omitempty"`

	// Internal fields (not serialized)
	duration time.Duration `json:"-"`
	err      error         `json:"-"`
}

// SetDuration sets the duration and calculates DurationSeconds
func (r *Result) SetDuration(d time.Duration) {
	r.duration = d
	r.DurationSeconds = d.Seconds()
}

// GetDuration returns the internal duration
func (r *Result) GetDuration() time.Duration {
	return r.duration
}

// SetError sets the error and ErrorMessage
func (r *Result) SetError(err error) {
	r.err = err
	if err != nil {
		r.ErrorMessage = err.Error()
	}
}

// GetError returns the internal error
func (r *Result) GetError() error {
	return r.err
}

// ToJSON converts the Result to a JSON string
func (r *Result) ToJSON() (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Check defines the interface that all Zygarde Cells must implement.
// Each Cell is a specialized monitoring unit that observes a specific aspect
// of the kernel for rootkit activity.
type Check interface {
	// Name returns the short name of the Cell
	Name() string

	// Description returns a human-readable description of what this Cell monitors
	Description() string

	// Run activates the Cell and returns the result of its observation
	Run() (Result, error)

	// Cleanup deactivates the Cell and releases resources (closing eBPF programs, etc.)
	Cleanup() error
}

// Debuggable is an optional interface for Cells that support debug logging
type Debuggable interface {
	// SetDebug enables or disables debug mode for this Cell
	SetDebug(bool)
}
