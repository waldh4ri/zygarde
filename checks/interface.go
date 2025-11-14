package checks

import "time"

// Status represents the result status of a forensic check
type Status int

const (
	// StatusOK indicates the check passed without issues
	StatusOK Status = iota
	// StatusSuspicious indicates potential rootkit activity detected
	StatusSuspicious
	// StatusError indicates the check encountered an error
	StatusError
)

// String returns the string representation of the status
func (s Status) String() string {
	switch s {
	case StatusOK:
		return "OK"
	case StatusSuspicious:
		return "SUSPICIOUS"
	case StatusError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Finding represents a single suspicious discovery
type Finding struct {
	// Description of what was found
	Description string
	// Details provides additional context
	Details map[string]string
}

// Result represents the outcome of running a check
type Result struct {
	// Status is the overall status of the check
	Status Status
	// Message provides a summary of the check result
	Message string
	// Findings contains detailed suspicious items found
	Findings []Finding
	// Duration is how long the check took to run
	Duration time.Duration
	// Error contains any error that occurred
	Error error
}

// Check defines the interface that all forensic checks must implement
type Check interface {
	// Name returns the short name of the check
	Name() string
	
	// Description returns a human-readable description of what this check does
	Description() string
	
	// Run executes the check and returns the result
	Run() (Result, error)
	
	// Cleanup performs any necessary cleanup (closing eBPF programs, etc.)
	Cleanup() error
}

// Debuggable is an optional interface for checks that support debug logging
type Debuggable interface {
	// SetDebug enables or disables debug mode
	SetDebug(bool)
}
