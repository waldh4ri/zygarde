//go:build ignore

// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Usermode helpers: read the kernel's own copy of the programs it runs as
// root (modprobe_path, core_pattern, uevent_helper, poweroff_cmd).

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "zygarde.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_STRS 8
#define STR_LEN  256

// Set by userspace before loading: kernel addresses, checked to lie in the
// kernel image's data, and how many bytes each string may span.
const volatile __u32 nr_strs = 0;
const volatile __u64 addrs[MAX_STRS] = {};
const volatile __u32 lens[MAX_STRS] = {};

struct kstr {
	__u32 fired;
	__s32 err; // bpf_probe_read_kernel_str result: length with the NUL, or -errno
	char str[STR_LEN];
};

const struct kstr *unused_kstr __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_STRS);
	__type(key, __u32);
	__type(value, struct kstr);
} strs SEC(".maps");

// Attached to getuid(); zygarde calls getuid() to trigger the read.
SEC("kprobe")
int read_strs(void *ctx)
{
	if (!is_target())
		return 0;

#pragma unroll
	for (int i = 0; i < MAX_STRS; i++) {
		if (i < nr_strs) {
			__u32 key = i;
			struct kstr *s = bpf_map_lookup_elem(&strs, &key);
			__u32 n = lens[i];

			if (!s)
				continue;
			if (n > STR_LEN || n == 0)
				n = STR_LEN;
			s->fired = 1;
			s->err = bpf_probe_read_kernel_str(s->str, n, (void *)addrs[i]);
		}
	}
	return 0;
}
