//go:build ignore

// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// File descriptor ownership: which processes hold BPF objects, BPF-attached
// perf events and sockets, read from every task's file table.

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Kinds of files reported (fdowner.Kind).
#define KIND_PROG   1
#define KIND_MAP    2
#define KIND_LINK   3
#define KIND_PERF   4
#define KIND_SOCKET 5
#define NR_KINDS    6

struct fd_rec {
	__u32 tgid;    // holder, in zygarde's PID namespace
	__u32 fd;
	__u32 kind;
	__u32 id;      // program, map or link ID
	__u32 prog_id; // program a link or perf event runs
	__u32 pad;
	__u64 fop;     // f_op address (learning pass only)
	__u64 ino;     // socket inode
	char comm[16];
};

const struct fd_rec *unused_fd_rec __attribute__((unused));

// fops[kind] is the file_operations address of that kind of file. Userspace
// learns them from its own descriptors (first pass, with the map empty), so
// no data symbol has to be resolved through /proc/kallsyms.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_KINDS);
	__type(key, __u32);
	__type(value, __u64);
} fops SEC(".maps");

static __always_inline __u32 pid_nr(struct pid *pid, __u32 level)
{
	struct upid upid = {};

	if (!pid || BPF_CORE_READ(pid, level) < level)
		return 0;
	bpf_core_read(&upid, sizeof(upid), &pid->numbers[level]);
	return upid.nr;
}

static __always_inline __u32 kind_of(__u64 fop)
{
#pragma unroll
	for (__u32 k = KIND_PROG; k < NR_KINDS; k++) {
		__u32 key = k;
		__u64 *v = bpf_map_lookup_elem(&fops, &key);

		if (v && *v && *v == fop)
			return k;
	}
	return 0;
}

SEC("iter/task_file")
int dump_fds(struct bpf_iter__task_file *ctx)
{
	struct task_struct *task = ctx->task;
	struct file *file = ctx->file;
	struct task_struct *self = (struct task_struct *)bpf_get_current_task();
	struct fd_rec rec = {};
	__u32 key = KIND_PROG, level;
	__u64 *learned, fop;
	void *priv;

	if (!task || !file)
		return 0;

	fop = (__u64)BPF_CORE_READ(file, f_op);
	learned = bpf_map_lookup_elem(&fops, &key);
	if (!learned || !*learned) {
		// Learning pass: report zygarde's own files with their f_op.
		if (BPF_CORE_READ(task, tgid) != BPF_CORE_READ(self, tgid))
			return 0;
		rec.fd = ctx->fd;
		rec.fop = fop;
		bpf_seq_write(ctx->meta->seq, &rec, sizeof(rec));
		return 0;
	}

	rec.kind = kind_of(fop);
	if (!rec.kind)
		return 0;

	priv = BPF_CORE_READ(file, private_data);
	switch (rec.kind) {
	case KIND_PROG:
		rec.id = BPF_CORE_READ((struct bpf_prog *)priv, aux, id);
		break;
	case KIND_MAP:
		rec.id = BPF_CORE_READ((struct bpf_map *)priv, id);
		break;
	case KIND_LINK:
		rec.id = BPF_CORE_READ((struct bpf_link *)priv, id);
		rec.prog_id = BPF_CORE_READ((struct bpf_link *)priv, prog, aux, id);
		break;
	case KIND_PERF:
		// Only perf events running a BPF program are of interest.
		if (!bpf_core_field_exists(((struct perf_event *)priv)->prog))
			return 0;
		rec.prog_id = BPF_CORE_READ((struct perf_event *)priv, prog, aux, id);
		if (!rec.prog_id)
			return 0;
		break;
	case KIND_SOCKET:
		rec.ino = BPF_CORE_READ(file, f_inode, i_ino);
		break;
	}

	level = BPF_CORE_READ(self, thread_pid, level);
	rec.tgid = pid_nr(BPF_CORE_READ(task, group_leader, thread_pid), level);
	rec.fd = ctx->fd;
	BPF_CORE_READ_STR_INTO(&rec.comm, task, comm);
	bpf_seq_write(ctx->meta->seq, &rec, sizeof(rec));
	return 0;
}
