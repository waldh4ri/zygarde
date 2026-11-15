//go:build ignore

// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Namespace membership: the namespaces every thread of the system lives in,
// read from the kernel's task list. A namespace that appears here has a task;
// one that something else keeps alive (a bind mount of its nsfs file, an open
// descriptor, a socket) and that appears nowhere here is an orphan.

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct ns_rec {
	__u32 tgid;  // process ID, in zygarde's PID namespace
	__u32 tid;
	__u32 mnt;   // inode numbers of the namespaces (nsfs inode == ns_common.inum)
	__u32 net;
	__u32 pid;
	__u32 pid_children;
	__u32 ipc;
	__u32 uts;
	__u32 user;
	__u32 cgroup;
	__u32 time;
	__u32 time_children;
	char comm[16];
};

const struct ns_rec *unused_ns_rec __attribute__((unused));

static __always_inline __u32 pid_nr(struct pid *pid, __u32 level)
{
	struct upid upid = {};

	if (!pid || BPF_CORE_READ(pid, level) < level)
		return 0;
	bpf_core_read(&upid, sizeof(upid), &pid->numbers[level]);
	return upid.nr;
}

// The PID namespace a task lives in: the namespace of its own struct pid.
static __always_inline __u32 task_pid_ns(struct task_struct *task)
{
	struct pid *pid = BPF_CORE_READ(task, thread_pid);
	struct pid_namespace *pns;
	struct upid upid = {};
	__u32 level;

	if (!pid)
		return 0;
	level = BPF_CORE_READ(pid, level);
	if (level > 32)
		return 0;
	bpf_core_read(&upid, sizeof(upid), &pid->numbers[level]);
	pns = upid.ns;
	return pns ? BPF_CORE_READ(pns, ns.inum) : 0;
}

SEC("iter/task")
int dump_ns(struct bpf_iter__task *ctx)
{
	struct task_struct *task = ctx->task;
	struct task_struct *self = (struct task_struct *)bpf_get_current_task();
	struct task_struct *leader;
	struct ns_rec rec = {};
	struct nsproxy *nsp;
	__u32 level;

	if (!task)
		return 0;
	// An exiting task has already dropped its namespaces.
	nsp = BPF_CORE_READ(task, nsproxy);
	if (!nsp)
		return 0;

	level = BPF_CORE_READ(self, thread_pid, level);
	leader = BPF_CORE_READ(task, group_leader);
	rec.tgid = pid_nr(BPF_CORE_READ(leader, thread_pid), level);
	rec.tid = pid_nr(BPF_CORE_READ(task, thread_pid), level);
	rec.mnt = BPF_CORE_READ(nsp, mnt_ns, ns.inum);
	rec.net = BPF_CORE_READ(nsp, net_ns, ns.inum);
	rec.ipc = BPF_CORE_READ(nsp, ipc_ns, ns.inum);
	rec.uts = BPF_CORE_READ(nsp, uts_ns, ns.inum);
	rec.cgroup = BPF_CORE_READ(nsp, cgroup_ns, ns.inum);
	rec.pid_children = BPF_CORE_READ(nsp, pid_ns_for_children, ns.inum);
	rec.pid = task_pid_ns(task);
	rec.user = BPF_CORE_READ(task, cred, user_ns, ns.inum);
	if (bpf_core_field_exists(nsp->time_ns)) {
		rec.time = BPF_CORE_READ(nsp, time_ns, ns.inum);
		rec.time_children = BPF_CORE_READ(nsp, time_ns_for_children, ns.inum);
	}
	if (leader)
		BPF_CORE_READ_STR_INTO(&rec.comm, leader, comm);
	else
		BPF_CORE_READ_STR_INTO(&rec.comm, task, comm);
	bpf_seq_write(ctx->meta->seq, &rec, sizeof(rec));
	return 0;
}
