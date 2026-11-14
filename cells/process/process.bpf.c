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
	__u64 start_time;  // the process's start (its leader's start_boottime, ns):
	                   // tells a reused PID apart; /proc/<pid>/stat shows it in ticks
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

// A plain (preallocated) hash, not an LRU: LRU maps updated from scheduler
// tracepoints can deadlock inside their own list locks. When it is full,
// new threads are counted in ran_dropped and reported as a limitation.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32); // init-namespace thread ID
	__type(value, struct sched_seen);
} ran SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} ran_dropped SEC(".maps");

#ifndef E2BIG
#define E2BIG 7
#endif

static __always_inline void record(__u32 tid, struct sched_seen *seen, __u64 flags)
{
	__u32 key = 0;
	__u64 *n;

	if (bpf_map_update_elem(&ran, &tid, seen, flags) != -E2BIG)
		return;
	n = bpf_map_lookup_elem(&ran_dropped, &key);
	if (n)
		__sync_fetch_and_add(n, 1);
}

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
	record(tid, &seen, BPF_NOEXIST);
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
	record(tid, &exited, BPF_ANY);
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

// ---------------------------------------------------------------------------
// Mount view: walks the mount tree of every mount namespace (iter/task, once
// per namespace) and reports each mount with the fields needed to spot mounts
// over /proc/<pid>. The kernel's tree (mount->mnt_mounts / mnt_child) is what
// path lookup and umount use; /proc/<pid>/mountinfo and /etc/mtab are only
// rendered from it, so a rootkit that filters those still shows up here.
// ---------------------------------------------------------------------------

#define PROC_SUPER_MAGIC 0x9fa0
#define MOUNT_NAME_LEN 16
#define MOUNT_PATH_DEPTH 4  // dentry names kept for a mount point inside procfs
#define MAX_STEPS 6000      // tree steps per namespace: about 6000 mounts
#define MOUNT_BATCH 100     // steps per iterator call: records of 152 bytes, so a call writes about 15 KB

#define MOUNT_REC_MOUNT 1
#define MOUNT_REC_NS 2
#define MOUNT_REC_ROOT 3 // a root mount of some process: mnt_id (the mount), parent_id (the PID of one process on it)

// Kernels before 6.8 call the mount count "mounts" (6.8+ has nr_mounts).
struct mnt_namespace___old {
	unsigned int mounts;
} __attribute__((preserve_access_index));

struct mount_rec {
	__u32 kind;         // MOUNT_REC_MOUNT, or MOUNT_REC_NS: one summary per namespace
	__u32 ns_inum;
	__u32 mnt_id;
	__u32 parent_id;
	__u32 magic;        // filesystem magic of the mounted filesystem
	__u32 parent_magic; // filesystem magic of the filesystem mounted on
	__u32 flags;        // MNT_* flags
	__u32 path_depth;   // names stored in path (0 unless the mount is on procfs)
	__u32 path_root;    // 1 when path reaches the root of the parent filesystem
	__u32 claimed;      // MOUNT_REC_NS: mounts the namespace says it has
	__u32 visited;      // MOUNT_REC_NS: mounts reached walking the tree
	__u32 truncated;    // MOUNT_REC_NS: 1 when the walk did not finish
	__u32 pad;
	__u64 mountpoint;   // dentry the mount covers (an identity, never printed)
	__u64 root_dentry;  // root dentry of the mounted filesystem
	char path[MOUNT_PATH_DEPTH][MOUNT_NAME_LEN]; // mount point names, innermost first
	char root[MOUNT_NAME_LEN];                   // name of the mounted directory
	char dev[MOUNT_NAME_LEN];                    // mnt_devname
};

const struct mount_rec *unused_mount_rec __attribute__((unused));

// Namespaces (and root mounts) already dumped in this run. Userspace empties it between runs.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u8);
} seen_mnt_ns SEC(".maps");

static __always_inline __u32 fs_magic(struct super_block *sb)
{
	return sb ? (__u32)BPF_CORE_READ(sb, s_magic) : 0;
}

static __always_inline struct mount *mount_of_child(void *node)
{
	return (struct mount *)((char *)node - bpf_core_field_offset(struct mount, mnt_child));
}

static __always_inline void dentry_name(char *dst, struct dentry *d)
{
	const unsigned char *name = BPF_CORE_READ(d, d_name.name);

	if (name)
		bpf_probe_read_kernel_str(dst, MOUNT_NAME_LEN, name);
}

// State of one walk, kept as plain integers so that walk_step() can be a
// global function: the verifier checks those once instead of once per loop
// iteration, which is what keeps the walk within its complexity limit.
struct walk {
	__u64 root;
	__u64 cur;
	__u32 ns_inum;
	__u32 visited;
	__u32 up;   // going back up: the current mount's subtree is done
	__u32 done;
	__u32 emit; // rec holds a mount to report
	__u32 active;  // a walk is in progress (it continues over several iterator calls)
	__u32 steps;   // steps taken so far
	__u32 claimed; // mounts the namespace says it has
	__u32 pad;
	struct mount_rec rec;
};

// The walk in progress, kept between iterator calls.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct walk);
} walk_state SEC(".maps");

static __always_inline void fill_mount(struct walk *w, struct mount *m)
{
	struct mount_rec *rec = &w->rec;
	struct mount *parent = BPF_CORE_READ(m, mnt_parent);
	struct dentry *mp = BPF_CORE_READ(m, mnt_mountpoint);
	struct dentry *root = BPF_CORE_READ(m, mnt.mnt_root);
	const char *dev = BPF_CORE_READ(m, mnt_devname);

	__builtin_memset(rec, 0, sizeof(*rec));
	rec->kind = MOUNT_REC_MOUNT;
	rec->ns_inum = w->ns_inum;
	rec->mnt_id = BPF_CORE_READ(m, mnt_id);
	rec->parent_id = parent ? BPF_CORE_READ(parent, mnt_id) : 0;
	rec->magic = fs_magic(BPF_CORE_READ(m, mnt.mnt_sb));
	rec->parent_magic = parent ? fs_magic(BPF_CORE_READ(parent, mnt.mnt_sb)) : 0;
	rec->flags = BPF_CORE_READ(m, mnt.mnt_flags);
	rec->mountpoint = (__u64)mp;
	rec->root_dentry = (__u64)root;
	if (root)
		dentry_name(rec->root, root);
	if (dev)
		bpf_probe_read_kernel_str(rec->dev, sizeof(rec->dev), dev);
	// Where the mount sits inside procfs: the names from the mount point up to
	// the filesystem's root (/proc/1234 gives "1234").
	if (rec->parent_magic == PROC_SUPER_MAGIC && mp) {
		struct dentry *d = mp;

		for (int i = 0; i < MOUNT_PATH_DEPTH; i++) {
			struct dentry *up = BPF_CORE_READ(d, d_parent);

			if (!up || up == d) {
				rec->path_root = 1;
				break;
			}
			dentry_name(rec->path[i], d);
			rec->path_depth = i + 1;
			d = up;
		}
	}
	w->emit = 1;
}

// One step of a depth-first walk over the mount tree, with no stack: report
// the current mount and go to its first child; with no child, go to the next
// sibling, or up to the parent when there is none.
__attribute__((noinline)) int walk_step(struct walk *w)
{
	struct mount *cur = (struct mount *)w->cur;
	struct mount *root = (struct mount *)w->root;
	struct mount *parent;
	void *first, *next;

	// Global functions take nullable pointers; the barrier stops clang from
	// dropping the check because w is dereferenced below.
	asm volatile("" : "+r"(w));
	if (!w)
		return 1;
	w->emit = 0;
	if (!cur) {
		w->done = 1;
		return 1;
	}
	if (!w->up) {
		fill_mount(w, cur);
		w->visited++;
		first = BPF_CORE_READ(cur, mnt_mounts.next);
		if (first && first != (char *)cur + bpf_core_field_offset(struct mount, mnt_mounts)) {
			w->cur = (__u64)mount_of_child(first);
			return 0;
		}
		w->up = 1;
	}
	if (cur == root) {
		w->done = 1;
		return 1;
	}
	parent = BPF_CORE_READ(cur, mnt_parent);
	next = BPF_CORE_READ(cur, mnt_child.next);
	if (!parent || parent == cur) {
		w->done = 1;
		return 1;
	}
	if (next && next != (char *)parent + bpf_core_field_offset(struct mount, mnt_mounts)) {
		w->cur = (__u64)mount_of_child(next);
		w->up = 0;
		return 0;
	}
	w->cur = (__u64)parent;
	return 0;
}

SEC("iter/task")
int dump_mounts(struct bpf_iter__task *ctx)
{
	struct task_struct *task = ctx->task;
	struct nsproxy *nsp;
	struct mnt_namespace *ns;
	struct walk *w;
	__u32 zero = 0;
	__u64 key;
	__u8 one = 1;

	if (!task || BPF_CORE_READ(task, pid) != BPF_CORE_READ(task, tgid))
		return 0;
	nsp = BPF_CORE_READ(task, nsproxy);
	ns = nsp ? BPF_CORE_READ(nsp, mnt_ns) : NULL;
	w = bpf_map_lookup_elem(&walk_state, &zero);
	if (!ns || !w)
		return 0;

	// A process only sees the mounts below its own root: say which one that is.
	{
		struct task_struct *self = (struct task_struct *)bpf_get_current_task();
		struct fs_struct *fs = BPF_CORE_READ(task, fs);
		struct vfsmount *vfs = fs ? BPF_CORE_READ(fs, root.mnt) : NULL;
		struct mount *rm = vfs ? (struct mount *)((char *)vfs - bpf_core_field_offset(struct mount, mnt)) : NULL;
		__u64 rkey = (__u64)rm;

		// One record per distinct root mount: a process on it is a reader of the view it gives.
		if (rm && !bpf_map_lookup_elem(&seen_mnt_ns, &rkey)) {
			bpf_map_update_elem(&seen_mnt_ns, &rkey, &one, BPF_ANY);
			__builtin_memset(&w->rec, 0, sizeof(w->rec));
			w->rec.kind = MOUNT_REC_ROOT;
			w->rec.ns_inum = BPF_CORE_READ(ns, ns.inum);
			w->rec.mnt_id = BPF_CORE_READ(rm, mnt_id);
			w->rec.parent_id = pid_nr(BPF_CORE_READ(task, group_leader, thread_pid), BPF_CORE_READ(self, thread_pid, level));
			bpf_seq_write(ctx->meta->seq, &w->rec, sizeof(w->rec));
		}
	}

	// One iterator call may write at most 64 KB, far less than a big mount
	// tree: a walk goes on over the next calls, in batches, and userspace
	// reads the iterator again until nothing is left.
	if (!w->active) {
		key = (__u64)ns;
		if (bpf_map_lookup_elem(&seen_mnt_ns, &key))
			return 0;
		bpf_map_update_elem(&seen_mnt_ns, &key, &one, BPF_ANY);
		__builtin_memset(w, 0, offsetof(struct walk, rec));
		w->root = (__u64)BPF_CORE_READ(ns, root);
		w->cur = w->root;
		w->ns_inum = BPF_CORE_READ(ns, ns.inum);
		if (bpf_core_field_exists(ns->nr_mounts))
			w->claimed = BPF_CORE_READ(ns, nr_mounts);
		else
			w->claimed = BPF_CORE_READ((struct mnt_namespace___old *)ns, mounts);
		w->active = 1;
	}

	for (int step = 0; step < MOUNT_BATCH; step++) {
		int stop = walk_step(w);

		if (w->emit)
			bpf_seq_write(ctx->meta->seq, &w->rec, sizeof(w->rec));
		if (!stop && ++w->steps < MAX_STEPS)
			continue;
		// The namespace summary reuses the record buffer.
		__builtin_memset(&w->rec, 0, sizeof(w->rec));
		w->rec.kind = MOUNT_REC_NS;
		w->rec.ns_inum = w->ns_inum;
		w->rec.claimed = w->claimed;
		w->rec.visited = w->visited;
		w->rec.truncated = !w->done;
		bpf_seq_write(ctx->meta->seq, &w->rec, sizeof(w->rec));
		w->active = 0;
		break;
	}
	return 0;
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
	if (bpf_core_field_exists(task->start_boottime)) {
		info.start_boottime = BPF_CORE_READ(task, start_boottime);
		info.start_time = BPF_CORE_READ(task, group_leader, start_boottime);
	} else {
		info.start_boottime = BPF_CORE_READ(task, start_time);
		info.start_time = BPF_CORE_READ(task, group_leader, start_time);
	}
	BPF_CORE_READ_STR_INTO(&info.comm, task, comm);

	bpf_seq_write(ctx->meta->seq, &info, sizeof(info));
	return 0;
}
