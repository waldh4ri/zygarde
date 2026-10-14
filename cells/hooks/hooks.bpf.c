//go:build ignore

// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Hook inventory canary: a do-nothing fentry hook that the inventory must find.

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// The attach target is set at load time (getppid's syscall handler).
SEC("fentry/placeholder")
int BPF_PROG(canary_fentry)
{
	return 0;
}

// Fallback for kernels without BPF trampolines: a kprobe on the function
// entry is implemented with ftrace too (CONFIG_KPROBES_ON_FTRACE).
SEC("kprobe")
int canary_kprobe(void *ctx)
{
	return 0;
}
