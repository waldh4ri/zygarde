// Package process detects processes hidden from /proc.
package process

//go:generate go tool bpf2go -target amd64,arm64 -cflags "-Wall -Werror -Wno-missing-declarations" -type task_info -type sched_seen process process.bpf.c -- -I../../bpf/include

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/canary"
	"github.com/waldh4ri/zygarde/internal/core"
)

// Cell compares the kernel's task list (BPF task iterator) with the process
// directories listed in /proc.
//
// /proc lists only thread-group leaders, so the comparison is per process
// (TGID). The kernel is snapshotted before and after reading /proc; a process
// only counts as hidden if it is in both snapshots, which rules out processes
// that started or exited during the scan.
type Cell struct{}

// New returns the hidden process Cell.
func New() *Cell { return &Cell{} }

func (*Cell) ID() string             { return "hidden_process" }
func (*Cell) Name() string           { return "Hidden Process Detection" }
func (*Cell) Timeout() time.Duration { return 30 * time.Second }
func (*Cell) Description() string {
	return "Compares the kernel task list (BPF task iterator) with the processes listed in /proc, and flags processes disguised as kernel threads or running from deleted or memory-backed files"
}

func (*Cell) Supported(env *core.Env) error {
	if err := env.RequireBTFType("bpf_iter__task", "the BPF task iterator (Linux 5.8+)"); err != nil {
		return err
	}
	if env.Lockdown == "confidentiality" {
		// Translating PIDs into our namespace needs bpf_probe_read_kernel().
		return core.Skip("kernel lockdown (confidentiality) forbids reading kernel memory from BPF")
	}
	// Both views must use the same PID namespace or the numbers won't match.
	self, err := os.Readlink("/proc/self")
	if err != nil {
		return fmt.Errorf("reading /proc/self: %w", err)
	}
	if self != strconv.Itoa(os.Getpid()) {
		return core.Skip("/proc belongs to a different PID namespace than zygarde")
	}
	return nil
}

// sampleWindow is how long the scheduler view records running tasks.
const sampleWindow = 2 * time.Second

func (*Cell) Run(ctx context.Context, env *core.Env, rec *core.Recorder) error {
	spec, err := loadProcess()
	if err != nil {
		return err
	}
	var iter struct {
		DumpTask *ebpf.Program `ebpf:"dump_task"`
	}
	if err := bpfutil.Load(env, spec, &iter); err != nil {
		return err
	}
	defer iter.DumpTask.Close()

	sched, err := startScheduler(env, spec, rec)
	if err != nil {
		return err
	}
	defer sched.Close()

	cp, err := canary.StartProcess()
	if err != nil {
		return err
	}
	defer cp.Stop()
	canaryPID := uint32(cp.PID())

	before, err := kernelTasks(iter.DumpTask)
	if err != nil {
		return err
	}
	listed, err := procPIDs()
	if err != nil {
		return err
	}
	if sched != nil {
		select {
		case <-time.After(sampleWindow):
		case <-ctx.Done():
			return ctx.Err()
		}
		sched.stopSampling() // keep tracking exits until the last snapshot
	}
	after, err := kernelTasks(iter.DumpTask)
	if err != nil {
		return err
	}

	name := fmt.Sprintf("process %d", canaryPID)
	_, inKernel := before.procs[canaryPID]
	rec.Canary(name, "BPF task iterator", inKernel)
	rec.Canary(name, "/proc directory listing", listed[canaryPID])

	for tgid, t := range before.procs {
		if _, stillThere := after.procs[tgid]; !stillThere || listed[tgid] || tgid == 0 {
			continue
		}
		comm := bpfutil.Int8String(t.Comm[:])
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("Process %d (%s) exists in the kernel but is hidden from /proc", tgid, comm),
			Details: map[string]string{
				"pid":   strconv.Itoa(int(tgid)),
				"comm":  comm,
				"ppid":  strconv.Itoa(int(t.Ppid)),
				"state": strconv.Itoa(int(t.State)),
			},
			Why: "Every process has a directory in /proc, which ps, top and most tools read. This one is running " +
				"but filtered out of the /proc listing, so those tools can't see it.",
			Benign: "None expected: the process was seen in two kernel snapshots taken around the /proc listing.",
		})
	}

	ran := 0
	if sched != nil {
		self := before.procs[uint32(os.Getpid())]
		ran, err = sched.check(rec, before, after, self.GlobalTgid)
		if err != nil {
			return err
		}
	}

	hidden := len(rec.Findings())

	// Disguised processes, checked on the kernel's view of every process.
	stable := make(map[uint32]processTaskInfo, len(before.procs))
	for tgid, t := range before.procs {
		if _, ok := after.procs[tgid]; ok && tgid != 0 {
			stable[tgid] = t
		}
	}
	checkMasquerade(rec, stable, map[uint32]bool{uint32(os.Getpid()): true, canaryPID: true})
	disguised := len(rec.Findings()) - hidden

	switch {
	case hidden > 0 && disguised > 0:
		rec.Message("%d hidden and %d disguised process(es)", hidden, disguised)
	case hidden > 0:
		rec.Message("%d hidden process(es) or task(s)", hidden)
	case disguised > 0:
		rec.Message("No hidden processes; %d disguised process(es)", disguised)
	case sched != nil:
		rec.Message("No hidden processes (%d kernel processes, %d /proc entries, %d threads seen running)", len(before.procs), len(listed), ran)
	default:
		rec.Message("No hidden processes (%d kernel processes, %d /proc entries)", len(before.procs), len(listed))
	}
	return nil
}

// snapshot is one pass of the task iterator.
type snapshot struct {
	procs   map[uint32]processTaskInfo // by TGID in zygarde's namespace, leader preferred
	threads map[uint32]bool            // init-namespace thread IDs
}

func kernelTasks(prog *ebpf.Program) (snapshot, error) {
	s := snapshot{procs: map[uint32]processTaskInfo{}, threads: map[uint32]bool{}}
	data, err := bpfutil.ReadIter(prog)
	if err != nil {
		return s, err
	}
	tasks, err := bpfutil.Decode[processTaskInfo](data)
	if err != nil {
		return s, err
	}
	for _, t := range tasks {
		s.threads[t.GlobalPid] = true
		if t.Tgid == 0 {
			continue // not representable in our PID namespace
		}
		if _, seen := s.procs[t.Tgid]; !seen || t.Pid == t.Tgid {
			s.procs[t.Tgid] = t
		}
	}
	return s, nil
}

// scheduler records which threads run, independently of the PID table.
type scheduler struct {
	switchLink, exitLink link.Link
	progs                struct {
		OnSchedSwitch *ebpf.Program `ebpf:"on_sched_switch"`
		OnSchedExit   *ebpf.Program `ebpf:"on_sched_exit"`
		Ran           *ebpf.Map     `ebpf:"ran"`
	}
}

// startScheduler attaches the scheduler view, or returns nil if it doesn't
// apply here: it needs BTF-typed tracepoints and the initial PID namespace
// (the task iterator only sees zygarde's own namespace).
func startScheduler(env *core.Env, spec *ebpf.CollectionSpec, rec *core.Recorder) (*scheduler, error) {
	if env.BTF == nil {
		return nil, nil
	}
	if _, err := env.BTF.AnyTypeByName("btf_trace_sched_switch"); err != nil {
		rec.Limit("Scheduler view not run: the kernel lacks BTF-typed tracepoints (Linux 5.5+), so tasks removed from the PID table can't be detected")
		return nil, nil
	}
	if init, err := bpfutil.InInitPIDNS(); err != nil || !init {
		rec.Limit("Scheduler view not run: zygarde is not in the initial PID namespace (e.g. inside a container), so tasks removed from the PID table can't be detected")
		return nil, nil
	}
	s := &scheduler{}
	if err := bpfutil.Load(env, spec, &s.progs); err != nil {
		return nil, err
	}
	var err error
	if s.exitLink, err = link.AttachTracing(link.TracingOptions{Program: s.progs.OnSchedExit}); err != nil {
		s.Close()
		return nil, core.WrapBPF("attach tp_btf/sched_process_exit", err)
	}
	if s.switchLink, err = link.AttachTracing(link.TracingOptions{Program: s.progs.OnSchedSwitch}); err != nil {
		s.Close()
		return nil, core.WrapBPF("attach tp_btf/sched_switch", err)
	}
	return s, nil
}

func (s *scheduler) stopSampling() {
	if s.switchLink != nil {
		s.switchLink.Close()
		s.switchLink = nil
	}
}

func (s *scheduler) Close() {
	if s == nil {
		return
	}
	s.stopSampling()
	if s.exitLink != nil {
		s.exitLink.Close()
	}
	for _, c := range []interface{ Close() error }{s.progs.OnSchedSwitch, s.progs.OnSchedExit, s.progs.Ran} {
		if c != nil {
			c.Close()
		}
	}
}

// check reports threads that ran during the window but are in neither task
// iterator snapshot and did not exit. It returns how many threads ran.
func (s *scheduler) check(rec *core.Recorder, before, after snapshot, selfTgid uint32) (int, error) {
	type entry struct {
		tid  uint32
		seen processSchedSeen
	}
	var all []entry
	var tid uint32
	var seen processSchedSeen
	it := s.progs.Ran.Iterate()
	for it.Next(&tid, &seen) {
		all = append(all, entry{tid, seen})
	}
	if err := it.Err(); err != nil {
		return 0, core.WrapBPF("iterate scheduler map", err)
	}

	sawSelf := false
	for _, e := range all {
		if e.seen.Tgid == selfTgid {
			sawSelf = true
		}
		if e.seen.Exited != 0 || before.threads[e.tid] || after.threads[e.tid] {
			continue
		}
		// The exit probe is still attached: give a thread exiting right now
		// a moment to be marked before calling it hidden.
		var again processSchedSeen
		time.Sleep(100 * time.Millisecond)
		if err := s.progs.Ran.Lookup(e.tid, &again); err == nil && again.Exited != 0 {
			continue
		}
		comm := bpfutil.Int8String(e.seen.Comm[:])
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("Thread %d (%s, process %d) ran on a CPU but is missing from the kernel's PID table", e.tid, comm, e.seen.Tgid),
			Details: map[string]string{
				"global_tid":  strconv.Itoa(int(e.tid)),
				"global_tgid": strconv.Itoa(int(e.seen.Tgid)),
				"comm":        comm,
			},
			Why: "The scheduler ran this thread, yet the kernel's PID table, which every process listing relies on, " +
				"has no entry for it. Removing a task from that table hides it from all tools while it keeps running.",
			Benign: "None expected: threads that exited during the check are excluded.",
		})
	}
	rec.Canary(fmt.Sprintf("zygarde (process %d)", selfTgid), "scheduler (sched_switch)", sawSelf)
	return len(all), nil
}

// procPIDs lists the numeric entries of /proc. This goes through getdents64,
// the syscall rootkits typically hook to hide processes.
func procPIDs() (map[uint32]bool, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("listing /proc: %w", err)
	}
	pids := make(map[uint32]bool, len(entries))
	for _, e := range entries {
		if pid, err := strconv.ParseUint(e.Name(), 10, 32); err == nil {
			pids[uint32(pid)] = true
		}
	}
	return pids, nil
}
