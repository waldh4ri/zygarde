//go:build ignore

// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Kernel memory reader: copies kernel memory at addresses chosen by
// userspace, which walks kernel structures with offsets from BTF. Reads go
// through bpf_probe_read_kernel(), which returns an error instead of
// faulting on freed or unmapped memory.

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "zygarde.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_READS 64
#define CHUNK     256

// One read. len 0 ends the batch; seq tags the batch so userspace can tell
// fresh results from stale ones.
struct kmem_req {
	__u64 addr;
	__u32 len;
	__u32 seq;
};

struct kmem_chunk {
	__u32 seq;
	__s32 err; // bpf_probe_read_kernel result: 0 or -errno
	__u8 data[CHUNK];
};

const struct kmem_req *unused_kmem_req __attribute__((unused));
const struct kmem_chunk *unused_kmem_chunk __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_READS);
	__type(key, __u32);
	__type(value, struct kmem_req);
} reqs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_READS);
	__type(key, __u32);
	__type(value, struct kmem_chunk);
} chunks SEC(".maps");

// Attached to getuid(); zygarde calls getuid() to run a batch. Userspace
// only passes kernel-half addresses away from the vsyscall page (kmem.go).
SEC("kprobe")
int read_kmem(void *ctx)
{
	if (!is_target())
		return 0;

#pragma unroll
	for (int i = 0; i < MAX_READS; i++) {
		__u32 key = i;
		struct kmem_req *r = bpf_map_lookup_elem(&reqs, &key);
		struct kmem_chunk *c = bpf_map_lookup_elem(&chunks, &key);
		__u32 n;

		if (!r || !c || r->len == 0)
			return 0;
		n = r->len;
		if (n > CHUNK || n == 0)
			n = CHUNK;
		c->seq = r->seq;
		c->err = bpf_probe_read_kernel(c->data, n, (void *)r->addr);
	}
	return 0;
}
