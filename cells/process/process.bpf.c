//go:build ignore

// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Hidden process detection: dump every task from the PID IDR (iter/task),
// walk init_task.tasks directly via open-coded task iterators on Linux 6.7+,
// and sample the scheduler (tp_btf/sched_switch).

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define PF_EXITING 0x00000004 /* include/linux/sched.h; same value in 5.4 and current kernels */

// Kernels before 5.14 name the field "state" instead of "__state".
struct task_struct___old {
	long state;
} __attribute__((preserve_access_index));

struct task_info {
	__u32 tgid;           // process ID, in zygarde's PID namespace
	__u32 pid;            // thread ID, in zygarde's PID namespace
	__u32 ppid;           // 0 if the parent is outside zygarde's PID namespace
	__u32 state;
	__u32 global_tgid;    // init-namespace IDs, to match scheduler & init_task views
	__u32 global_pid;
	__u32 flags;          // PF_* (PF_KTHREAD: a kernel thread)
	__u32 has_mm;         // has a user address space
	__u32 uid;
	__u32 euid;
	__u32 gid;
	__u32 pad;
	__u64 start_boottime; // nanoseconds since boot
	char comm[16];
};

// Emit task_info into BTF so bpf2go generates a Go type for it.
const struct task_info *unused_task_info __attribute__((unused));

// ---------------------------------------------------------------------------
// Scheduler view: every thread that gets switched in during the sampling
// window. A task removed from the PID table no longer shows up in /proc or
// in the task iterator, but it still has to be scheduled to run.
// ---------------------------------------------------------------------------

struct sched_seen {
	__u32 tgid;   // init namespace
	__u32 exited; // exited during the window: absent from snapshots legitimately
	char comm[16];
};

const struct sched_seen *unused_sched_seen __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32); // init-namespace thread ID
	__type(value, struct sched_seen);
} ran SEC(".maps");

// Arguments: (bool preempt, struct task_struct *prev, struct task_struct *next
// [, unsigned int prev_state since 5.18]); only next is used.
SEC("tp_btf/sched_switch")
int BPF_PROG(on_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	__u32 tid = next->pid;
	struct sched_seen seen = {};

	// Exiting tasks keep being scheduled after sched_process_exit, then
	// leave the PID table normally: ignore them (PF_EXITING is set first).
	if (tid == 0 || (next->flags & PF_EXITING))
		return 0;
	if (bpf_map_lookup_elem(&ran, &tid))
		return 0;
	seen.tgid = next->tgid;
	for (int i = 0; i < sizeof(seen.comm); i++)
		seen.comm[i] = next->comm[i];
	bpf_map_update_elem(&ran, &tid, &seen, BPF_NOEXIST);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_sched_exit, struct task_struct *p)
{
	__u32 tid = p->pid;
	struct sched_seen *seen = bpf_map_lookup_elem(&ran, &tid);
	struct sched_seen exited = { .exited = 1 };

	if (seen) {
		seen->exited = 1;
		return 0;
	}
	// Not seen running yet: record the exit so later switches are ignored.
	exited.tgid = p->tgid;
	bpf_map_update_elem(&ran, &tid, &exited, BPF_ANY);
	return 0;
}

// ---------------------------------------------------------------------------
// init_task.tasks view (Linux 6.7+): walks the global task list via
// bpf_iter_task_new/next rather than the PID IDR, catching sleeping tasks
// unlinked from pid_namespace->idr. Loaded only when kernel BTF supports it.
// ---------------------------------------------------------------------------

const volatile __u32 walk_target_tgid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32); // init-namespace thread ID (task->pid)
	__type(value, struct sched_seen);
} tasklist SEC(".maps");

SEC("raw_tp/sys_enter")
int walk_init_tasks(struct bpf_raw_tracepoint_args *ctx)
{
	struct bpf_iter_task it;
	struct task_struct *t;
	__u32 caller_tgid = bpf_get_current_pid_tgid() >> 32;

	if (!walk_target_tgid || caller_tgid != walk_target_tgid)
		return 0;

	bpf_rcu_read_lock();
	bpf_iter_task_new(&it, NULL, 1 /* BPF_TASK_ITER_ALL_THREADS */);
	while ((t = bpf_iter_task_next(&it))) {
		__u32 tid = BPF_CORE_READ(t, pid);
		__u32 flags = BPF_CORE_READ(t, flags);
		struct sched_seen seen = {};

		if (tid == 0 || (flags & PF_EXITING))
			continue;
		seen.tgid = BPF_CORE_READ(t, tgid);
		BPF_CORE_READ_STR_INTO(&seen.comm, t, comm);
		bpf_map_update_elem(&tasklist, &tid, &seen, BPF_ANY);
	}
	bpf_iter_task_destroy(&it);
	bpf_rcu_read_unlock();
	return 0;
}

// pid_nr returns the number of pid in the namespace at the given level,
// like the kernel's pid_nr_ns(). task->pid and task->tgid are init-namespace
// numbers, which don't match /proc inside a container.
static __always_inline __u32 pid_nr(struct pid *pid, __u32 level)
{
	struct upid upid = {};

	if (!pid || BPF_CORE_READ(pid, level) < level)
		return 0;
	bpf_core_read(&upid, sizeof(upid), &pid->numbers[level]);
	return upid.nr;
}

// The iterator walks the PID namespace of the process reading it (zygarde),
// whose level is that of its own struct pid.
SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
	struct task_struct *task = ctx->task;
	struct task_struct *self = (struct task_struct *)bpf_get_current_task();
	struct task_info info = {};
	const struct cred *cred;
	__u32 level;

	if (!task)
		return 0;

	level = BPF_CORE_READ(self, thread_pid, level);
	info.tgid = pid_nr(BPF_CORE_READ(task, group_leader, thread_pid), level);
	info.pid = pid_nr(BPF_CORE_READ(task, thread_pid), level);
	info.ppid = pid_nr(BPF_CORE_READ(task, real_parent, group_leader, thread_pid), level);
	info.global_tgid = BPF_CORE_READ(task, tgid);
	info.global_pid = BPF_CORE_READ(task, pid);
	if (bpf_core_field_exists(task->__state))
		info.state = BPF_CORE_READ(task, __state);
	else
		info.state = BPF_CORE_READ((struct task_struct___old *)task, state);
	info.flags = BPF_CORE_READ(task, flags);
	info.has_mm = BPF_CORE_READ(task, mm) != NULL;
	cred = BPF_CORE_READ(task, cred);
	if (cred) {
		info.uid = BPF_CORE_READ(cred, uid.val);
		info.euid = BPF_CORE_READ(cred, euid.val);
		info.gid = BPF_CORE_READ(cred, gid.val);
	}
	if (bpf_core_field_exists(task->start_boottime))
		info.start_boottime = BPF_CORE_READ(task, start_boottime);
	else
		info.start_boottime = BPF_CORE_READ(task, start_time);
	BPF_CORE_READ_STR_INTO(&info.comm, task, comm);

	bpf_seq_write(ctx->meta->seq, &info, sizeof(info));
	return 0;
}
