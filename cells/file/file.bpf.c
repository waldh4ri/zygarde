//go:build ignore

// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Hidden directory entries & VFS f_op integrity: record every entry the
// filesystem hands to getdents64() for zygarde's own directory listings, track
// ring buffer drops, and capture file->f_op->iterate_shared pointers.

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "zygarde.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_NAME 256

struct dirent_event {
	__u32 namlen;
	char name[MAX_NAME];
};

const struct dirent_event *unused_dirent_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

// Counts dropped dirent events when a huge directory bursts faster than
// userspace drains the ring buffer, preventing silent blind spots or false
// missing-canary alerts.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drop_cnt SEC(".maps");

// Records file->f_op->iterate_shared for directories zygarde lists, keyed by
// directory inode, to catch VFS function-pointer swaps on /proc, /sys, /, etc.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 256);
	__type(key, __u64);
	__type(value, __u64);
} dir_fops SEC(".maps");

// filldir64(struct dir_context *ctx, const char *name, int namlen, ...) is
// the callback filesystems call (through dir_emit()) for each entry they
// produce during getdents64(). Anything that filters entries afterwards, by
// hooking the syscall or rewriting the user buffer, can't hide them from here.
SEC("kprobe")
int on_filldir64(struct pt_regs *ctx)
{
	const char *name = (const char *)PT_REGS_PARM2(ctx);
	__u32 len = (__u32)PT_REGS_PARM3(ctx);
	struct dirent_event *e;

	if (!is_target())
		return 0;
	if (len == 0 || len >= MAX_NAME)
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		__u32 zero = 0;
		__u64 *drops = bpf_map_lookup_elem(&drop_cnt, &zero);
		if (drops)
			__sync_fetch_and_add(drops, 1);
		return 0;
	}
	// Names are not NUL-terminated (e.g. ext4 dirents): copy exactly len bytes.
	e->namlen = len;
	if (bpf_probe_read_kernel(e->name, len & (MAX_NAME - 1), name)) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// iterate_dir(struct file *file, struct dir_context *ctx) dispatches through
// file->f_op->iterate_shared. A rootkit that swaps that function pointer can
// skip calling filldir64 altogether; recording the target pointer exposes it.
SEC("kprobe")
int on_iterate_dir(struct pt_regs *ctx)
{
	struct file *file = (struct file *)PT_REGS_PARM1(ctx);
	__u64 ino, fn;

	if (!is_target() || !file)
		return 0;

	ino = BPF_CORE_READ(file, f_inode, i_ino);
	fn = (__u64)BPF_CORE_READ(file, f_op, iterate_shared);
	if (ino && fn)
		bpf_map_update_elem(&dir_fops, &ino, &fn, BPF_ANY);
	return 0;
}
