package core

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// RunCell runs one Cell and turns its observations and error into a Result.
func RunCell(ctx context.Context, env *Env, c Cell) (res Result) {
	start := time.Now()
	res = Result{Cell: c.ID(), Name: c.Name()}
	res.SetStatus(StatusOK)
	log := env.Log.With("cell", c.ID())

	defer func() {
		if p := recover(); p != nil {
			log.Error("cell panicked", "panic", p, "stack", string(debug.Stack()))
			res.SetStatus(StatusError)
			res.Error = fmt.Sprintf("panic: %v", p)
		}
		res.DurationSeconds = time.Since(start).Seconds()
	}()

	if err := c.Supported(env); err != nil {
		applyError(env, &res, err)
		return res
	}

	rec := NewRecorder(log)
	ctx, cancel := context.WithTimeout(ctx, c.Timeout())
	defer cancel()
	err := c.Run(ctx, env, rec)

	res.Message = rec.message
	res.Findings = rec.findings
	res.Observations = rec.observed
	res.Canaries = rec.canaries
	res.Limitations = rec.limitations()
	if len(res.Findings) > 0 {
		res.Escalate(StatusSuspicious)
	}
	for _, cc := range res.Canaries {
		if !cc.Observed {
			res.Escalate(StatusSuspicious)
			res.Findings = append(res.Findings, Finding{
				Description: fmt.Sprintf("Canary %s was not visible in %s", cc.Canary, cc.View),
				Details:     map[string]string{"canary": cc.Canary, "view": cc.View},
				Why: "Zygarde created this object itself just before looking for it. If a view can't show it, " +
					"that view is being filtered, and the Cell's clean answers for it can't be trusted.",
				Benign: "Very unusual; a security product sandboxing or filtering zygarde's own activity could cause it.",
			})
		}
	}
	if err != nil {
		applyError(env, &res, err)
	}
	return res
}

// applyError classifies err and records it on res.
func applyError(env *Env, res *Result, err error) {
	status, finding := Classify(env, err)
	if status == StatusSkipped {
		if len(res.Findings) == 0 {
			res.SetStatus(StatusSkipped)
		}
		res.Message = err.Error()
		return
	}
	res.Escalate(status)
	res.Error = err.Error()
	if finding != nil {
		res.Findings = append(res.Findings, *finding)
	}
}

// Classify decides what an error from a Cell means:
//   - SkipError or ebpf.ErrNotSupported: the kernel doesn't support it (SKIPPED)
//   - a bpf() permission error although Env says eBPF should work: the scanner
//     is likely being blocked (SUSPICIOUS, with a finding explaining why)
//   - anything else: ERROR
func Classify(env *Env, err error) (Status, *Finding) {
	var skip *SkipError
	if errors.As(err, &skip) {
		return StatusSkipped, nil
	}
	if errors.Is(err, ebpf.ErrNotSupported) {
		return StatusSkipped, nil
	}

	var be *BPFError
	if errors.As(err, &be) && (errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES)) {
		if expected, why := env.BPFExpected(); expected {
			return StatusSuspicious, &Finding{
				Description: fmt.Sprintf("bpf() %s was denied although this process should be allowed to use eBPF", be.Op),
				Details: map[string]string{
					"operation":   be.Op,
					"error":       be.Err.Error(),
					"environment": why,
				},
				Why: "Root without a seccomp filter is normally allowed to use eBPF. A rootkit that intercepts bpf() " +
					"can refuse it to blind scanners like this one.",
				Benign: "A security policy restricting eBPF: SELinux, AppArmor or a BPF-LSM program. Check the audit log for denials.",
			}
		}
	}
	return StatusError, nil
}
