//go:build ignore

// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Executable memory of every process, read from the kernel's VMA tree
// (iter/task_vma, Linux 5.12+), to compare with /proc/<pid>/maps.

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define VM_EXEC 0x00000004 /* include/linux/mm.h; unchanged since 2.6 */

struct vma_rec {
	__u32 tgid;       // process ID in zygarde's PID namespace (0: outside it)
	__u32 file;       // 1 when the mapping is backed by a file
	__u64 start;
	__u64 end;
	__u64 flags;      // vm_flags
	__u64 ino;        // inode of the mapped file
	__u64 start_time; // the process's start (group leader's start_boottime), against PID reuse
};

const struct vma_rec *unused_vma_rec __attribute__((unused));

static __always_inline __u32 pid_nr(struct pid *pid, __u32 level)
{
	struct upid upid = {};

	if (!pid || BPF_CORE_READ(pid, level) < level)
		return 0;
	bpf_core_read(&upid, sizeof(upid), &pid->numbers[level]);
	return upid.nr;
}

SEC("iter/task_vma")
int dump_vma(struct bpf_iter__task_vma *ctx)
{
	struct vm_area_struct *vma = ctx->vma;
	struct task_struct *task = ctx->task;
	struct task_struct *self = (struct task_struct *)bpf_get_current_task();
	struct vma_rec rec = {};
	struct file *f;

	if (!task || !vma)
		return 0;
	rec.flags = BPF_CORE_READ(vma, vm_flags);
	if (!(rec.flags & VM_EXEC))
		return 0;
	rec.tgid = pid_nr(BPF_CORE_READ(task, group_leader, thread_pid), BPF_CORE_READ(self, thread_pid, level));
	if (!rec.tgid)
		return 0;
	rec.start = BPF_CORE_READ(vma, vm_start);
	rec.end = BPF_CORE_READ(vma, vm_end);
	f = BPF_CORE_READ(vma, vm_file);
	if (f) {
		rec.file = 1;
		rec.ino = BPF_CORE_READ(f, f_inode, i_ino);
	}
	if (bpf_core_field_exists(task->start_boottime))
		rec.start_time = BPF_CORE_READ(task, group_leader, start_boottime);
	else // RHEL 8's 4.18 has the iterator but not this field
		rec.start_time = BPF_CORE_READ(task, group_leader, start_time);
	bpf_seq_write(ctx->meta->seq, &rec, sizeof(rec));
	return 0;
}
