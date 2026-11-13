package taint

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/kmsg"
)

// taintDie is the kernel taint bit set by an oops or BUG (TAINT_DIE, 'D').
const taintDie = 7

// maxOopsFindings bounds how many oopses are reported individually.
const maxOopsFindings = 5

// checkOopses reports kernel oopses: the ones still in the kernel log, and an
// oops the log no longer holds when the 'D' taint says one happened. It
// returns the number of findings.
//
// A healthy host rarely oopses at all, and one that does while root reads
// sysfs or procfs is the signature of a rootkit that left kernel objects
// dangling. Zygarde's own earlier scans can be the trigger, which is then the
// evidence: the faulting task is named in the finding.
func (c *Cell) checkOopses(rec *core.Recorder, mask uint64) int {
	if c.kmsg == nil {
		return 0 // no kernel log source configured
	}
	died := mask&(1<<taintDie) != 0
	recs, err := c.kmsg()
	if err != nil {
		if died {
			rec.Limit("The kernel log could not be read (%v), so the oops behind taint 'D' is not shown", err)
		}
		return 0
	}
	oopses := kmsg.Oopses(recs, 0)
	if len(oopses) == 0 {
		if !died {
			return 0
		}
		rec.Suspicious(core.Finding{
			Description: "The kernel oopsed since boot (taint 'D') but the kernel log no longer holds the oops",
			Details:     map[string]string{"taint": "D", "kernel_mask": strconv.FormatUint(mask, 10)},
			Why:         oopsWhy,
			Benign:      oopsBenign,
		})
		return 1
	}
	if len(oopses) > maxOopsFindings {
		rec.Limit("%d kernel oopses in the log, the latest %d are reported", len(oopses), maxOopsFindings)
		oopses = oopses[len(oopses)-maxOopsFindings:]
	}
	for _, o := range oopses {
		d := map[string]string{
			"oops":          o.Headline,
			"function":      o.IP,
			"seconds_after": fmt.Sprintf("%.1f", float64(o.TimeUS)/1e6),
		}
		if o.Comm != "" {
			d["faulting_task"] = fmt.Sprintf("%s (%d)", o.Comm, o.PID)
		}
		if len(o.Trace) > 0 {
			d["call_trace"] = strings.Join(o.Trace, " < ")
		}
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("The kernel oopsed since boot: %s", o.Summary()),
			Details:     d,
			Why:         oopsWhy,
			Benign:      oopsBenign,
		})
	}
	return len(oopses)
}

const oopsWhy = "A healthy kernel does not oops. One that does while a process reads ordinary sysfs or procfs files means " +
	"the kernel followed a corrupt or dangling pointer behind them: a kernel module freed or overwrote the object that " +
	"backs the file. Rootkits do this when they hide (Diamorphine frees its module's section attributes and leaves " +
	"/sys/module/<name>/sections/* pointing at them), and a tool that reads those files triggers the fault."

const oopsBenign = "A bug in a driver or in the kernel. Check the faulting function and call trace against known bug " +
	"reports, and whether the module involved is expected on this host."
