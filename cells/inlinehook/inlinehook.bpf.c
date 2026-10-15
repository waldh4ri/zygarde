//go:build ignore

// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Inline hook detection: read the first bytes of kernel functions.

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "zygarde.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_FUNCS  64
#define CODE_BYTES 16

// Set by userspace before loading.
const volatile __u32 nr_funcs = 0;
const volatile __u64 addrs[MAX_FUNCS] = {};

struct func_code {
	__u8 bytes[CODE_BYTES];
};

const struct func_code *unused_func_code __attribute__((unused));

// prologues[i] = the first CODE_BYTES bytes at addrs[i]
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_FUNCS);
	__type(key, __u32);
	__type(value, struct func_code);
} prologues SEC(".maps");

// Attached to getuid(); zygarde calls getuid() to trigger the read.
SEC("kprobe")
int read_code(void *ctx)
{
	if (!is_target())
		return 0;

	// Unrolled: the 5.10 verifier rejects this bounded loop as infinite.
#pragma unroll
	for (int i = 0; i < MAX_FUNCS; i++) {
		if (i < nr_funcs) {
			__u32 key = i;
			struct func_code c = {};

			bpf_probe_read_kernel(&c.bytes, sizeof(c.bytes), (void *)addrs[i]);
			bpf_map_update_elem(&prologues, &key, &c, BPF_ANY);
		}
	}
	return 0;
}
