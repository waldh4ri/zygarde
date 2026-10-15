package core

import "encoding/json"

// Status is the outcome of a Cell.
type Status int

const (
	// StatusOK means the Cell ran and found nothing.
	StatusOK Status = 0
	// StatusError means the Cell could not complete its analysis.
	StatusError Status = 1
	// StatusSuspicious means the Cell found evidence of tampering.
	StatusSuspicious Status = 2
	// StatusSkipped means the Cell does not apply to this system.
	StatusSkipped Status = 3
)

func (s Status) String() string {
	switch s {
	case StatusOK:
		return "OK"
	case StatusError:
		return "ERROR"
	case StatusSuspicious:
		return "SUSPICIOUS"
	case StatusSkipped:
		return "SKIPPED"
	default:
		return "UNKNOWN"
	}
}

// MarshalJSON encodes the status as its integer value.
func (s Status) MarshalJSON() ([]byte, error) {
	return json.Marshal(int(s))
}

// Finding is a single suspicious observation, written for the person who
// has to act on it.
type Finding struct {
	// Description says what was observed, in one sentence.
	Description string `json:"description"`
	// Details holds the evidence (identifiers, paths, addresses).
	Details map[string]string `json:"details,omitempty"`
	// Why explains why this points to tampering.
	Why string `json:"why,omitempty"`
	// Benign lists innocent explanations to rule out first.
	Benign string `json:"benign_causes,omitempty"`
}

// CanaryCheck records whether a known, planted object was seen in one view.
// A missing canary means that view is not reporting the truth.
type CanaryCheck struct {
	Canary   string `json:"canary"`
	View     string `json:"view"`
	Observed bool   `json:"observed"`
}

// Result is the outcome of running one Cell.
type Result struct {
	Cell            string        `json:"cell"`
	Name            string        `json:"name"`
	Status          Status        `json:"status"`
	StatusText      string        `json:"status_text"`
	Message         string        `json:"message,omitempty"`
	Findings        []Finding     `json:"findings,omitempty"`
	Observations    []Finding     `json:"observations,omitempty"`
	Canaries        []CanaryCheck `json:"canaries,omitempty"`
	Limitations     []string      `json:"limitations,omitempty"`
	Error           string        `json:"error,omitempty"`
	DurationSeconds float64       `json:"duration_seconds"`
}

// SetStatus sets Status and keeps StatusText in sync.
func (r *Result) SetStatus(s Status) {
	r.Status = s
	r.StatusText = s.String()
}

// Escalate raises the status to s if s is more severe.
// Severity order: SKIPPED < OK < ERROR < SUSPICIOUS.
func (r *Result) Escalate(s Status) {
	if severity(s) > severity(r.Status) {
		r.SetStatus(s)
	}
}

func severity(s Status) int {
	switch s {
	case StatusSkipped:
		return 0
	case StatusOK:
		return 1
	case StatusError:
		return 2
	case StatusSuspicious:
		return 3
	default:
		return 0
	}
}

// ExitCode maps a set of results to the process exit code:
// 2 if anything is suspicious, 1 if any Cell errored, 0 otherwise.
func ExitCode(results []Result) int {
	code := 0
	for _, r := range results {
		switch r.Status {
		case StatusSuspicious:
			return 2
		case StatusError:
			code = 1
		}
	}
	return code
}
