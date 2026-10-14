//go:build ignore

// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Hidden eBPF program detection.

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "zygarde.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ---------------------------------------------------------------------------
// Kernel view: every loaded program, read from the program IDR.
// ---------------------------------------------------------------------------

struct prog_info {
	__u32 id;
	__u32 type;
	char name[16];
};

const struct prog_info *unused_prog_info __attribute__((unused));

SEC("iter/bpf_prog")
int dump_bpf_prog(struct bpf_iter__bpf_prog *ctx)
{
	struct bpf_prog *prog = ctx->prog;
	struct prog_info info = {};

	if (!prog)
		return 0;

	struct bpf_prog_aux *aux = prog->aux;
	info.id = aux->id;
	info.type = prog->type;
	for (int i = 0; i < sizeof(info.name); i++)
		info.name[i] = aux->name[i];

	bpf_seq_write(ctx->meta->seq, &info, sizeof(info));
	return 0;
}

// ---------------------------------------------------------------------------
// Syscall view: what bpf() really returned to zygarde's own *_GET_NEXT_ID
// calls, as seen at syscall exit.
// ---------------------------------------------------------------------------

#define CMD_PROG_GET_NEXT_ID 11


struct enum_call {
	__u64 attr;
	__u32 start_id;
};

struct enum_event {
	__u32 start_id;
	__s32 ret;
	__u32 next_id;
};

const struct enum_event *unused_enum_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64); // pid_tgid: per thread
	__type(value, struct enum_call);
} inflight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} enum_events SEC(".maps");

// tp_btf programs need no tracefs: they attach by BTF ID.
SEC("tp_btf/sys_enter")
int BPF_PROG(bpf_enter, struct pt_regs *regs, long nr)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enum_call call = {};

	if (nr != NR_bpf || PT_REGS_PARM1_SYSCALL(regs) != CMD_PROG_GET_NEXT_ID || !is_target())
		return 0;

	call.attr = PT_REGS_PARM2_SYSCALL(regs);
	bpf_probe_read_user(&call.start_id, sizeof(call.start_id), (void *)call.attr);
	bpf_map_update_elem(&inflight, &id, &call, BPF_ANY);
	return 0;
}

// Fires for every syscall exit; only threads with an entry in inflight are
// inside a traced bpf() call.
SEC("tp_btf/sys_exit")
int BPF_PROG(bpf_exit, struct pt_regs *regs, long ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enum_call *call = bpf_map_lookup_elem(&inflight, &id);
	struct enum_event *e;

	if (!call)
		return 0;

	e = bpf_ringbuf_reserve(&enum_events, sizeof(*e), 0);
	if (e) {
		e->start_id = call->start_id;
		e->ret = ret;
		e->next_id = 0;
		// union bpf_attr: start_id and next_id are the first two __u32s.
		if (ret == 0)
			bpf_probe_read_user(&e->next_id, sizeof(e->next_id), (void *)(call->attr + 4));
		bpf_ringbuf_submit(e, 0);
	}
	bpf_map_delete_elem(&inflight, &id);
	return 0;
}
