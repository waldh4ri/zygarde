//go:build ignore

// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Hidden directory entries: record every entry the filesystem hands to
// getdents64() for zygarde's own directory listings.

#include "vmlinux.h"
#include "bpf_helpers.h"
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

// drops[0] counts entries that could not be recorded (ring buffer full or
// unreadable name), so a lost entry is a coverage limit, not a missing canary.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

static __always_inline void count_drop(void)
{
	__u32 key = 0;
	__u64 *n = bpf_map_lookup_elem(&drops, &key);

	if (n)
		__sync_fetch_and_add(n, 1);
}

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
		count_drop();
		return 0;
	}
	// Names are not NUL-terminated (e.g. ext4 dirents): copy exactly len bytes.
	e->namlen = len;
	if (bpf_probe_read_kernel(e->name, len & (MAX_NAME - 1), name)) {
		bpf_ringbuf_discard(e, 0);
		count_drop();
		return 0;
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}
