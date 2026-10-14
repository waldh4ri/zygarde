//go:build ignore

// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Syscall table integrity: read sys_call_table entries from kernel memory.

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "zygarde.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_ENTRIES 64

// Set by userspace before loading.
const volatile __u64 table_addr = 0;
const volatile __u32 nr_count = 0;
const volatile __u32 nrs[MAX_ENTRIES] = {};

// entries[i] = sys_call_table[nrs[i]]
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, __u64);
} entries SEC(".maps");

// Attached to getuid(); zygarde calls getuid() once to trigger the read.
SEC("kprobe")
int read_table(void *ctx)
{
	if (!is_target())
		return 0;

	// Unrolled: the 5.10 verifier rejects this bounded loop as infinite.
	// nr_count is a load-time constant, so the verifier prunes unused copies.
#pragma unroll
	for (int i = 0; i < MAX_ENTRIES; i++) {
		if (i < nr_count) {
			__u32 key = i;
			__u64 handler = 0;

			bpf_probe_read_kernel(&handler, sizeof(handler),
					      (void *)(table_addr + (__u64)nrs[i] * sizeof(__u64)));
			bpf_map_update_elem(&entries, &key, &handler, BPF_ANY);
		}
	}
	return 0;
}
