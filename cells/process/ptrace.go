package process

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fsutil"
)

// traceEdge is one tracer attached to one process, with the threads it traces.
type traceEdge struct {
	tracee, tracer uint32 // process IDs
	tids           []uint32
	tracerTID      map[uint32]uint32 // traced thread -> tracing thread
}

// tracerPID reads TracerPid from /proc/<tgid>/task/<tid>/status.
func tracerPID(tgid, tid uint32) (uint32, bool) {
	f, err := fsutil.OpenNoAtime(fmt.Sprintf("/proc/%d/task/%d/status", tgid, tid))
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "TracerPid:"); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
			return uint32(n), err == nil
		}
	}
	return 0, false
}

// checkPtrace reports which processes are being traced (ptrace), from the
// kernel's task list. A tracer reads and writes the tracee's memory and
// registers: it is how code is injected into a running process (credential
// theft from sshd, a library loaded into a daemon). Debuggers do the same,
// so a trace is reported as suspicious only when the kernel and /proc
// disagree about it, or when the tracer runs from a fileless or out-of-place
// executable; other traces are observations.
func checkPtrace(rec *core.Recorder, before, after snapshot, listed map[uint32]bool, skip map[uint32]bool, alive func() (snapshot, error)) error {
	edges := map[[2]uint32]*traceEdge{}
	for tid, t := range before.nsThreads {
		if t.Ptraced == 0 || skip[t.Tgid] || tid == 0 {
			continue
		}
		a, ok := after.nsThreads[tid]
		if !ok || a.StartBoottime != t.StartBoottime || a.Ptraced == 0 || a.TracerPid != t.TracerPid {
			continue // attached or detached during the scan
		}
		key := [2]uint32{t.Tgid, t.TracerTgid}
		e := edges[key]
		if e == nil {
			e = &traceEdge{tracee: t.Tgid, tracer: t.TracerTgid, tracerTID: map[uint32]uint32{}}
			edges[key] = e
		}
		e.tids = append(e.tids, tid)
		e.tracerTID[tid] = t.TracerPid
	}
	if len(edges) == 0 {
		return nil
	}

	keys := make([][2]uint32, 0, len(edges))
	for k := range edges {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i][0] < keys[j][0] || keys[i][0] == keys[j][0] && keys[i][1] < keys[j][1]
	})

	// What /proc says, read once for every traced thread.
	type mismatch struct {
		tid, kernel, proc uint32
	}
	shown := map[[2]uint32][]mismatch{}
	_ = fsutil.WithComm("ps", func() error {
		for _, k := range keys {
			e := edges[k]
			sort.Slice(e.tids, func(i, j int) bool { return e.tids[i] < e.tids[j] })
			if e.tracer == 0 || !listed[e.tracee] {
				continue // traced from outside zygarde's PID namespace, or a hidden process (reported already)
			}
			for _, tid := range e.tids {
				if p, ok := tracerPID(e.tracee, tid); ok && p != e.tracerTID[tid] {
					shown[k] = append(shown[k], mismatch{tid, e.tracerTID[tid], p})
				}
			}
		}
		return nil
	})
	// Confirm against the kernel once more after reading /proc.
	now, err := alive()
	if err != nil {
		return err
	}
	still := func(tid, tracer uint32, start uint64) bool {
		t, ok := now.nsThreads[tid]
		return ok && t.StartBoottime == start && t.Ptraced != 0 && t.TracerPid == tracer
	}

	for _, k := range keys {
		e := edges[k]
		t := before.nsThreads[e.tids[0]]
		if !still(e.tids[0], t.TracerPid, t.StartBoottime) {
			continue
		}
		tracee := before.procs[e.tracee]
		traceeComm := bpfutil.Int8String(tracee.Comm[:])
		d := map[string]string{
			"pid":            strconv.Itoa(int(e.tracee)),
			"comm":           traceeComm,
			"euid":           strconv.Itoa(int(tracee.Euid)),
			"traced_threads": joinIDs(e.tids, 20),
		}
		if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", e.tracee)); err == nil {
			d["exe"] = exe
		}
		if e.tracer == 0 {
			rec.Observe(fmt.Sprintf("Process %d (%s) is traced (ptrace) from outside zygarde's PID namespace", e.tracee, traceeComm), d)
			continue
		}
		tr := before.procs[e.tracer]
		tracerComm := bpfutil.Int8String(tr.Comm[:])
		d["tracer_pid"] = strconv.Itoa(int(e.tracer))
		d["tracer_comm"] = tracerComm
		d["tracer_euid"] = strconv.Itoa(int(tr.Euid))
		tracerExe, exeErr := os.Readlink(fmt.Sprintf("/proc/%d/exe", e.tracer))
		if exeErr == nil {
			d["tracer_exe"] = tracerExe
		}
		if !listed[e.tracer] {
			d["tracer_hidden_from_proc"] = "true"
		}

		var lies []string
		for _, m := range shown[k] {
			if still(m.tid, m.kernel, before.nsThreads[m.tid].StartBoottime) {
				lies = append(lies, fmt.Sprintf("thread %d: TracerPid %d, kernel %d", m.tid, m.proc, m.kernel))
			}
		}
		if len(lies) > 0 {
			d["proc_status"] = strings.Join(lies, "; ")
			rec.Suspicious(core.Finding{
				Description: fmt.Sprintf("Process %d (%s) is traced by process %d (%s), but /proc/%d/status hides it", e.tracee, traceeComm, e.tracer, tracerComm, e.tracee),
				Details:     d,
				Why: "The kernel's task list says a tracer is attached to this process (PT_PTRACED, and the tracer is its " +
					"parent task), yet TracerPid in /proc/<pid>/status, which the kernel renders from the same fields, " +
					"shows another value. Something filters /proc to hide an injection in progress, or to defeat " +
					"anti-debugging checks that read TracerPid.",
				Benign: "None expected: the trace was seen in three kernel snapshots around the /proc read.",
			})
			continue
		}

		loc := ""
		if exeErr == nil {
			loc = exeLocation(tracerExe)
		}
		if suspiciousTracer(loc, tracerExe, tr.Euid) {
			d["tracer_location"] = loc
			rec.Suspicious(core.Finding{
				Description: fmt.Sprintf("Process %d (%s) is traced by process %d (%s), which runs from a %s executable: %s", e.tracee, traceeComm, e.tracer, tracerComm, loc, tracerExe),
				Details:     d,
				Why: "A tracer can read and rewrite the traced process's memory and registers: this is how code is " +
					"injected into a running daemon (credential theft from sshd, a library loaded into a service). " +
					"Debuggers are installed programs; a tracer that lives only in memory, in a temporary or hidden " +
					"directory, or was deleted, is an injector covering its tracks.",
				Benign: "A debugger or tracing tool built in or copied to /tmp by an administrator.",
			})
			continue
		}
		rec.Observe(fmt.Sprintf("Process %d (%s) is traced (ptrace) by process %d (%s, %s)", e.tracee, traceeComm, e.tracer, tracerComm, firstNonEmpty(tracerExe, "executable unknown")), d)
	}
	return nil
}

// suspiciousTracer says whether a tracer's executable location (exeLocation)
// marks it as an injector rather than a debugger. IDEs ship debuggers in
// hidden directories of their user's home (~/.vscode, ~/.local/share/JetBrains),
// so a hidden directory only counts for a root tracer.
func suspiciousTracer(loc, exe string, euid uint32) bool {
	switch loc {
	case "":
		return false
	case "deleted":
		return !packaged(strings.TrimSuffix(exe, " (deleted)"))
	case "hidden directory":
		return euid == 0
	}
	return true
}

func joinIDs(ids []uint32, max int) string {
	var s []string
	for i, id := range ids {
		if i == max {
			s = append(s, fmt.Sprintf("… (%d more)", len(ids)-max))
			break
		}
		s = append(s, strconv.Itoa(int(id)))
	}
	return strings.Join(s, ", ")
}
