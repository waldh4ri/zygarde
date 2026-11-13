// Package process detects processes and threads hidden from /proc or the PID
// table, as well as processes masquerading as kernel threads or running from
// deleted or memory-backed executables.
package process

//go:generate go tool bpf2go -target amd64,arm64 -cflags "-Wall -Werror -Wno-missing-declarations" -type task_info -type sched_seen process process.bpf.c -- -I../../bpf/include

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/canary"
	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fsutil"
)

// Cell compares the kernel's task views (BPF task iterator, init_task.tasks
// kfunc walk on Linux 6.7+, and scheduler tracepoints) with /proc.
type Cell struct{}

// New returns the hidden process Cell.
func New() *Cell { return &Cell{} }

func (*Cell) ID() string             { return "hidden_process" }
func (*Cell) Name() string           { return "Hidden Process Detection" }
func (*Cell) Timeout() time.Duration { return 30 * time.Second }
func (*Cell) Description() string {
	return "Compares kernel task views (BPF task iterator, init_task.tasks and scheduler) with /proc processes and threads, and flags disguised or fileless processes"
}

func (*Cell) Supported(env *core.Env) error {
	if err := env.RequireBTFType("bpf_iter__task", "the BPF task iterator (Linux 5.8+)"); err != nil {
		return err
	}
	if env.Lockdown == "confidentiality" {
		return core.Skip("kernel lockdown (confidentiality) forbids reading kernel memory from BPF")
	}
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
	if id, err := bpfutil.ProgramID(iter.DumpTask); err == nil {
		rec.Footprint("bpf_prog_id", strconv.FormatUint(uint64(id), 10))
	}

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
	rec.Footprint("canary_pid", strconv.FormatUint(uint64(canaryPID), 10))

	initBefore, haveInitWalk := snapshotInitTaskList(env, rec)
	before, err := kernelTasks(iter.DumpTask)
	if err != nil {
		return err
	}
	listed, err := procPIDs()
	if err != nil {
		return err
	}
	listedThreads := procThreads(listed)

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
	var initAfter map[uint32]processSchedSeen
	if haveInitWalk {
		initAfter, _ = snapshotInitTaskList(env, nil)
	}

	name := fmt.Sprintf("process %d", canaryPID)
	_, inKernel := before.procs[canaryPID]
	rec.Canary(name, "BPF task iterator", inKernel)
	rec.Canary(name, "/proc directory listing", listed[canaryPID])
	if haveInitWalk {
		if cInfo, ok := before.procs[canaryPID]; ok {
			_, inInit := initBefore[cInfo.GlobalPid]
			rec.Canary(name, "init_task.tasks walk", inInit)
		}
	}

	var tgidList []uint32
	for tgid := range before.procs {
		tgidList = append(tgidList, tgid)
	}
	sort.Slice(tgidList, func(i, j int) bool { return tgidList[i] < tgidList[j] })

	for _, tgid := range tgidList {
		t := before.procs[tgid]
		// Same process (matching start_time) in both snapshots rules out PID reuse.
		if a, stillThere := after.procs[tgid]; !stillThere || a.StartTime != t.StartTime || listed[tgid] || tgid == 0 {
			continue
		}
		comm := bpfutil.Int8String(t.Comm[:])
		d := map[string]string{
			"pid":   strconv.Itoa(int(tgid)),
			"comm":  comm,
			"ppid":  strconv.Itoa(int(t.Ppid)),
			"uid":   strconv.Itoa(int(t.Uid)),
			"euid":  strconv.Itoa(int(t.Euid)),
			"gid":   strconv.Itoa(int(t.Gid)),
			"state": strconv.Itoa(int(t.State)),
		}
		if ts := env.FormatBootOffset(t.StartTime); ts != "" {
			d["started_at"] = ts
		}
		enrichProcFiles(env, int(tgid), comm, d)
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("Process %d (%s) exists in the kernel but is hidden from /proc", tgid, comm),
			Details:     d,
			Why: "Every process has a directory in /proc, which ps, top and most tools read. This one is running " +
				"but filtered out of the /proc listing, so those tools can't see it.",
			Benign: "None expected: the process was seen in two kernel snapshots taken around the /proc listing.",
		})
	}

	// Hidden sub-threads inside visible processes (/proc/<tgid>/task/<tid>).
	for tid, t := range before.nsThreads {
		if tid == t.Tgid || tid == 0 || !listed[t.Tgid] {
			continue
		}
		if a, stillThere := after.nsThreads[tid]; !stillThere || a.StartBoottime != t.StartBoottime {
			continue
		}
		procTaskSet, ok := listedThreads[t.Tgid]
		if !ok || procTaskSet[tid] {
			continue
		}
		freshSet, err := readTaskDir(t.Tgid)
		if err != nil || freshSet[tid] {
			continue
		}
		if a2, stillAfter := readSingleThreadCheck(iter.DumpTask, tid); !stillAfter || a2.StartBoottime != t.StartBoottime {
			continue
		}
		comm := bpfutil.Int8String(t.Comm[:])
		d := map[string]string{
			"tid":  strconv.Itoa(int(tid)),
			"pid":  strconv.Itoa(int(t.Tgid)),
			"comm": comm,
			"euid": strconv.Itoa(int(t.Euid)),
		}
		if ts := env.FormatBootOffset(t.StartBoottime); ts != "" {
			d["started_at"] = ts
		}
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("Thread %d (%s) of process %d exists in the kernel but is hidden from /proc/%d/task", tid, comm, t.Tgid, t.Tgid),
			Details:     d,
			Why:         "Every thread of a process appears under /proc/<pid>/task. Hiding an injected thread while keeping its host process visible conceals execution inside trusted daemons.",
			Benign:      "None expected: the thread was present before and after reading /proc/<pid>/task.",
		})
	}

	// Tasks present on init_task.tasks (both snapshots) yet unlinked from PID IDR.
	reportedUnlinked := map[uint32]bool{}
	if haveInitWalk && initAfter != nil {
		for gtid, seen := range initBefore {
			if _, ok := initAfter[gtid]; !ok || before.threads[gtid] || after.threads[gtid] {
				continue
			}
			reportedUnlinked[gtid] = true
			comm := bpfutil.Int8String(seen.Comm[:])
			rec.Suspicious(core.Finding{
				Description: fmt.Sprintf("Task %d (%s, process %d) is on init_task.tasks but missing from the kernel's PID table", gtid, comm, seen.Tgid),
				Details: map[string]string{
					"global_tid":  strconv.Itoa(int(gtid)),
					"global_tgid": strconv.Itoa(int(seen.Tgid)),
					"comm":        comm,
				},
				Why: "Walking init_task.tasks found this task in kernel memory (even if sleeping), yet the PID " +
					"table (pid_namespace->idr) has no entry for it. Unlinking a task from the PID table hides it from /proc and standard iterators.",
				Benign: "None expected: the task persisted across two snapshots without exiting.",
			})
		}
	}

	ran := 0
	if sched != nil {
		self := before.procs[uint32(os.Getpid())]
		ran, err = sched.check(rec, before, after, self.GlobalTgid, reportedUnlinked)
		if err != nil {
			return err
		}
	}

	hidden := len(rec.Findings())

	// Disguised processes, checked on the kernel's view of every process and
	// re-confirmed against a fresh kernel snapshot after reading /proc/<pid>/*.
	stable := make(map[uint32]processTaskInfo, len(before.procs))
	for tgid, t := range before.procs {
		if a, ok := after.procs[tgid]; ok && a.StartTime == t.StartTime && tgid != 0 {
			stable[tgid] = t
		}
	}
	alive := func() (map[uint32]uint64, error) {
		now, err := kernelTasks(iter.DumpTask)
		if err != nil {
			return nil, err
		}
		starts := make(map[uint32]uint64, len(now.procs))
		for tgid, t := range now.procs {
			starts[tgid] = t.StartTime
		}
		return starts, nil
	}
	if err := checkMasquerade(env, rec, stable, map[uint32]bool{uint32(os.Getpid()): true, canaryPID: true}, alive); err != nil {
		return err
	}
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
	procs     map[uint32]processTaskInfo // by TGID in zygarde's namespace, leader preferred
	nsThreads map[uint32]processTaskInfo // by TID in zygarde's namespace
	threads   map[uint32]bool            // init-namespace thread IDs
}

func kernelTasks(prog *ebpf.Program) (snapshot, error) {
	s := snapshot{
		procs:     map[uint32]processTaskInfo{},
		nsThreads: map[uint32]processTaskInfo{},
		threads:   map[uint32]bool{},
	}
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
		if t.Pid != 0 {
			s.nsThreads[t.Pid] = t
		}
		if t.Tgid == 0 {
			continue
		}
		if _, seen := s.procs[t.Tgid]; !seen || t.Pid == t.Tgid {
			s.procs[t.Tgid] = t
		}
	}
	return s, nil
}

func readSingleThreadCheck(prog *ebpf.Program, tid uint32) (processTaskInfo, bool) {
	s, err := kernelTasks(prog)
	if err != nil {
		return processTaskInfo{}, false
	}
	t, ok := s.nsThreads[tid]
	return t, ok
}

func snapshotInitTaskList(env *core.Env, rec *core.Recorder) (map[uint32]processSchedSeen, bool) {
	if env.BTF == nil {
		return nil, false
	}
	if _, err := env.BTF.AnyTypeByName("bpf_iter_task_new"); err != nil {
		return nil, false
	}
	if init, err := bpfutil.InInitPIDNS(); err != nil || !init {
		return nil, false
	}
	spec, err := loadProcess()
	if err != nil {
		return nil, false
	}
	if err := bpfutil.SetVariable(spec, "walk_target_tgid", uint32(unix.Getpid())); err != nil {
		return nil, false
	}
	var objs struct {
		WalkInitTasks *ebpf.Program `ebpf:"walk_init_tasks"`
		Tasklist      *ebpf.Map     `ebpf:"tasklist"`
	}
	if err := bpfutil.Load(env, spec, &objs); err != nil {
		if rec != nil {
			rec.Log().Debug("init_task.tasks walk unavailable", "err", err)
		}
		return nil, false
	}
	defer objs.WalkInitTasks.Close()
	defer objs.Tasklist.Close()
	if rec != nil {
		if id, err := bpfutil.ProgramID(objs.WalkInitTasks); err == nil {
			rec.Footprint("bpf_prog_id", strconv.FormatUint(uint64(id), 10))
		}
	}

	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sys_enter", Program: objs.WalkInitTasks})
	if err != nil {
		if rec != nil {
			rec.Log().Debug("attach walk_init_tasks failed", "err", err)
		}
		return nil, false
	}
	unix.Getuid()
	l.Close()

	out := map[uint32]processSchedSeen{}
	var tid uint32
	var seen processSchedSeen
	it := objs.Tasklist.Iterate()
	for it.Next(&tid, &seen) {
		out[tid] = seen
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// scheduler records which threads run, independently of the PID table.
type scheduler struct {
	switchLink, exitLink link.Link
	progs                struct {
		OnSchedSwitch *ebpf.Program `ebpf:"on_sched_switch"`
		OnSchedExit   *ebpf.Program `ebpf:"on_sched_exit"`
		Ran           *ebpf.Map     `ebpf:"ran"`
		RanDropped    *ebpf.Map     `ebpf:"ran_dropped"`
	}
}

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
	for _, p := range []*ebpf.Program{s.progs.OnSchedSwitch, s.progs.OnSchedExit} {
		if id, err := bpfutil.ProgramID(p); err == nil {
			rec.Footprint("bpf_prog_id", strconv.FormatUint(uint64(id), 10))
		}
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
	for _, c := range []*ebpf.Program{s.progs.OnSchedSwitch, s.progs.OnSchedExit} {
		if c != nil {
			c.Close()
		}
	}
	for _, m := range []*ebpf.Map{s.progs.Ran, s.progs.RanDropped} {
		if m != nil {
			m.Close()
		}
	}
}

func (s *scheduler) check(rec *core.Recorder, before, after snapshot, selfTgid uint32, alreadyReported map[uint32]bool) (int, error) {
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
	var dropped uint64
	if err := s.progs.RanDropped.Lookup(uint32(0), &dropped); err == nil && dropped > 0 {
		rec.Limit("Scheduler view: %d thread(s) ran after its table was full and were not checked", dropped)
	}

	sawSelf := false
	var candidates []entry
	for _, e := range all {
		if e.seen.Tgid == selfTgid {
			sawSelf = true
		}
		if e.seen.Exited != 0 || before.threads[e.tid] || after.threads[e.tid] || alreadyReported[e.tid] {
			continue
		}
		candidates = append(candidates, e)
	}
	if len(candidates) > 0 {
		time.Sleep(100 * time.Millisecond)
	}
	for _, e := range candidates {
		var again processSchedSeen
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

func procPIDs() (map[uint32]bool, error) {
	return fsutil.WithCommVal("ps", func() (map[uint32]bool, error) {
		entries, err := fsutil.ReadDirNoAtime("/proc")
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
	})
}

func procThreads(listed map[uint32]bool) map[uint32]map[uint32]bool {
	out := make(map[uint32]map[uint32]bool, len(listed))
	_ = fsutil.WithComm("ps", func() error {
		for tgid := range listed {
			if set, err := readTaskDirRaw(tgid); err == nil {
				out[tgid] = set
			}
		}
		return nil
	})
	return out
}

func readTaskDir(tgid uint32) (map[uint32]bool, error) {
	return fsutil.WithCommVal("ps", func() (map[uint32]bool, error) {
		return readTaskDirRaw(tgid)
	})
}

func readTaskDirRaw(tgid uint32) (map[uint32]bool, error) {
	entries, err := fsutil.ReadDirNoAtime(fmt.Sprintf("/proc/%d/task", tgid))
	if err != nil {
		return nil, err
	}
	tids := make(map[uint32]bool, len(entries))
	for _, e := range entries {
		if tid, err := strconv.ParseUint(e.Name(), 10, 32); err == nil {
			tids[uint32(tid)] = true
		}
	}
	return tids, nil
}

func enrichProcFiles(env *core.Env, pid int, comm string, d map[string]string) {
	dir := "/proc/" + strconv.Itoa(pid)
	if cwd, err := os.Readlink(dir + "/cwd"); err == nil && cwd != "" {
		d["cwd"] = cwd
	}
	if cg, err := fsutil.ReadFileNoAtime(dir + "/cgroup"); err == nil {
		if line := strings.TrimSpace(string(cg)); line != "" {
			d["cgroup"] = truncate(strings.ReplaceAll(line, "\n", "; "), 160)
		}
	}
	exeLink := dir + "/exe"
	if exe, err := os.Readlink(exeLink); err == nil && exe != "" {
		d["exe"] = exe
	}
	if sum, err := fsutil.SHA256File(exeLink); err == nil {
		d["exe_sha256"] = sum
	}
	if env != nil && env.Settings.PreserveDir != "" {
		if saved, sum, err := fsutil.PreserveBinary(exeLink, env.Settings.PreserveDir, fmt.Sprintf("pid-%d-%s", pid, comm)); err == nil && saved != "" {
			d["preserved_exe"] = saved
			if d["exe_sha256"] == "" && sum != "" {
				d["exe_sha256"] = sum
			}
		}
	}
}
