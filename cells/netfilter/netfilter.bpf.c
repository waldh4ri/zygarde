//go:build ignore

// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Netfilter hook inventory: the hook functions registered in every network
// namespace a task lives in, read from struct net (net->nf.hooks_*) and from
// each network device's ingress/egress hooks.

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define NFPROTO_IPV4   2
#define NFPROTO_ARP    3
#define NFPROTO_NETDEV 5
#define NFPROTO_BRIDGE 7
#define NFPROTO_IPV6   10

#define NF_INET_NUMHOOKS 5
#define NF_ARP_NUMHOOKS  3

#define MAX_HOOKS 24  // entries read per hook point
#define MAX_DEVS  32  // network devices walked per namespace
#define MAX_NETNS 4096

// nf_rec.kind
#define REC_NETNS 0 // one per namespace, after its chains
#define REC_CHAIN 1

// nf_rec.flags (REC_NETNS)
#define F_DEVS_TRUNCATED 1
#define F_NO_DEVS        2 // device hooks not readable on this kernel

struct nf_rec {
	__u32 inum;    // network namespace inode
	__u8 kind;
	__u8 pf;       // NFPROTO_*
	__u8 hook;     // hook number; for NFPROTO_NETDEV 0 = ingress, 1 = egress
	__u8 flags;
	__u32 num;     // num_hook_entries as read (may exceed MAX_HOOKS)
	__u32 ifindex;
	char dev[16];
	__u64 entries; // struct nf_hook_entries address
	__u64 hooks[MAX_HOOKS * 2]; // {hook, priv} pairs
};

const struct nf_rec *unused_nf_rec __attribute__((unused));

// Netfilter internals, declared here because not every vmlinux.h carries
// them (CONFIG_NETFILTER). CO-RE matches them to the running kernel by name.
struct nf_hook_entry___z {
	void *hook;
	void *priv;
};

struct nf_hook_entries___z {
	__u16 num_hook_entries;
	struct nf_hook_entry___z hooks[0];
} __attribute__((preserve_access_index));

struct netns_nf___z {
	struct nf_hook_entries___z *hooks_ipv4[NF_INET_NUMHOOKS];
	struct nf_hook_entries___z *hooks_ipv6[NF_INET_NUMHOOKS];
	struct nf_hook_entries___z *hooks_arp[NF_ARP_NUMHOOKS];
	struct nf_hook_entries___z *hooks_bridge[NF_INET_NUMHOOKS];
} __attribute__((preserve_access_index));

struct net___z {
	struct netns_nf___z nf;
} __attribute__((preserve_access_index));

// Device hooks: CONFIG_NETFILTER_INGRESS (4.16+) and CONFIG_NETFILTER_EGRESS
// (5.16+). Not every vmlinux.h has them, so declare the fields here.
struct net_device___nf {
	struct nf_hook_entries___z *nf_hooks_ingress;
	struct nf_hook_entries___z *nf_hooks_egress;
} __attribute__((preserve_access_index));

// Scratch record: too large for the BPF stack.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct nf_rec);
} scratch SEC(".maps");

// Namespaces already dumped, by struct net address.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_NETNS);
	__type(key, __u64);
	__type(value, __u8);
} seen SEC(".maps");

// stats[0]: namespaces not dumped because seen was full.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

// Only follow values that look like kernel addresses (see kptr.bpf.c).
static __always_inline bool kaddr(__u64 p)
{
#if defined(__TARGET_ARCH_x86)
	return p >= 0xff00000000000000ULL && p < 0xffffffffff000000ULL;
#else
	return p >= 0xff00000000000000ULL && p < 0xfffffffffffff000ULL;
#endif
}

static __always_inline void emit_chain(struct seq_file *seq, struct nf_rec *r, __u8 pf, __u8 hook,
				       struct nf_hook_entries___z *e)
{
	__u64 n, size;

	if (!kaddr((__u64)e))
		return;
	r->kind = REC_CHAIN;
	r->pf = pf;
	r->hook = hook;
	r->entries = (__u64)e;
	r->num = BPF_CORE_READ(e, num_hook_entries);
	n = r->num;
	if (n > MAX_HOOKS)
		n = MAX_HOOKS;
	size = n * sizeof(struct nf_hook_entry___z);
	// Keep the bound check next to the call so the verifier sees it.
	barrier_var(size);
	if (size > sizeof(r->hooks))
		size = sizeof(r->hooks);
	// One read of the hooks[] array that follows num_hook_entries.
	bpf_probe_read_kernel(r->hooks, size, (void *)e + bpf_core_field_offset(e->hooks));
	bpf_seq_write(seq, r, sizeof(*r));
}

SEC("iter/task")
int dump_hooks(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct nsproxy *nsp;
	struct net *net;
	struct net___z *nz;
	struct nf_rec *r;
	__u32 zero = 0;
	__u64 key;
	__u8 one = 1;
	void *head, *pos;

	if (!task)
		return 0;
	nsp = BPF_CORE_READ(task, nsproxy);
	if (!kaddr((__u64)nsp))
		return 0; // exiting task
	net = BPF_CORE_READ(nsp, net_ns);
	if (!kaddr((__u64)net))
		return 0;
	key = (__u64)net;
	if (bpf_map_lookup_elem(&seen, &key))
		return 0;
	if (bpf_map_update_elem(&seen, &key, &one, BPF_NOEXIST)) {
		__u64 *dropped = bpf_map_lookup_elem(&stats, &zero);

		if (dropped)
			__sync_fetch_and_add(dropped, 1);
		return 0;
	}
	r = bpf_map_lookup_elem(&scratch, &zero);
	if (!r)
		return 0;
	__builtin_memset(r, 0, sizeof(*r));
	r->inum = BPF_CORE_READ(net, ns.inum);
	nz = (struct net___z *)net;

#pragma unroll
	for (int i = 0; i < NF_INET_NUMHOOKS; i++) {
		emit_chain(seq, r, NFPROTO_IPV4, i, BPF_CORE_READ(nz, nf.hooks_ipv4[i]));
		if (bpf_core_field_exists(nz->nf.hooks_ipv6))
			emit_chain(seq, r, NFPROTO_IPV6, i, BPF_CORE_READ(nz, nf.hooks_ipv6[i]));
		if (bpf_core_field_exists(nz->nf.hooks_bridge))
			emit_chain(seq, r, NFPROTO_BRIDGE, i, BPF_CORE_READ(nz, nf.hooks_bridge[i]));
	}
	if (bpf_core_field_exists(nz->nf.hooks_arp)) {
#pragma unroll
		for (int i = 0; i < NF_ARP_NUMHOOKS; i++)
			emit_chain(seq, r, NFPROTO_ARP, i, BPF_CORE_READ(nz, nf.hooks_arp[i]));
	}

	// Per-device hooks (nftables netdev chains): walk net->dev_base_head.
	r->entries = 0;
	r->num = 0;
	if (bpf_core_field_exists(((struct net_device___nf *)0)->nf_hooks_ingress)) {
		head = (void *)net + bpf_core_field_offset(struct net, dev_base_head);
		pos = BPF_CORE_READ(net, dev_base_head.next);
#pragma unroll
		for (int i = 0; i < MAX_DEVS; i++) {
			struct net_device *dev;

			if (!kaddr((__u64)pos) || pos == head)
				break;
			dev = pos - bpf_core_field_offset(struct net_device, dev_list);
			r->ifindex = BPF_CORE_READ(dev, ifindex);
			BPF_CORE_READ_STR_INTO(&r->dev, dev, name);
			emit_chain(seq, r, NFPROTO_NETDEV, 0, BPF_CORE_READ((struct net_device___nf *)dev, nf_hooks_ingress));
			if (bpf_core_field_exists(((struct net_device___nf *)0)->nf_hooks_egress))
				emit_chain(seq, r, NFPROTO_NETDEV, 1,
					   BPF_CORE_READ((struct net_device___nf *)dev, nf_hooks_egress));
			pos = BPF_CORE_READ(dev, dev_list.next);
		}
		if (kaddr((__u64)pos) && pos != head)
			r->flags |= F_DEVS_TRUNCATED;
	} else {
		r->flags |= F_NO_DEVS;
	}

	r->kind = REC_NETNS;
	r->pf = 0;
	r->hook = 0;
	r->ifindex = 0;
	r->entries = 0;
	r->num = 0;
	__builtin_memset(r->dev, 0, sizeof(r->dev));
	bpf_seq_write(seq, r, sizeof(*r));
	return 0;
}

// Canary: a do-nothing BPF netfilter program (Linux 6.4+) attached to
// zygarde's own namespace, which must show up among its IPv4 hooks.
SEC("netfilter")
int canary(struct bpf_nf_ctx *ctx)
{
	return 1; // NF_ACCEPT
}
