//go:build ignore

// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Kernel socket view: walk TCP and UDP socket tables directly with BPF
// iterators so a rootkit filtering both /proc/net and netlink sock_diag still
// leaves a discrepancy against the kernel's own hash tables.

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define AF_INET_K  2
#define AF_INET6_K 10

#define PROTO_TCP 1
#define PROTO_UDP 2

#define TCP_TIME_WAIT_K    6
#define TCP_NEW_SYN_RECV_K 12

#if defined(__TARGET_ARCH_arm64)
struct bpf_iter__tcp {
	struct bpf_iter_meta *meta;
	struct sock_common *sk_common;
	uid_t uid;
} __attribute__((preserve_access_index));

struct bpf_iter__udp {
	struct bpf_iter_meta *meta;
	struct udp_sock *udp_sk;
	uid_t uid;
	int bucket;
} __attribute__((preserve_access_index));
#endif

struct bpf_sock_rec {
	__u64 ino;
	__u32 uid;
	__u16 sport;
	__u16 dport;
	__u8  proto;  // PROTO_TCP or PROTO_UDP
	__u8  family; // 4 or 6
	__u8  state;
	__u8  pad;
	__u8  src[16];
	__u8  dst[16];
	__u32 pad2;
};

const struct bpf_sock_rec *unused_bpf_sock_rec __attribute__((unused));

static __always_inline int emit_sock(struct seq_file *seq, struct sock *sk, __u8 proto, __u32 uid)
{
	struct bpf_sock_rec rec = {};
	__u16 fam;
	__u64 ino;

	if (!sk)
		return 0;

	rec.state = BPF_CORE_READ(sk, __sk_common.skc_state);
	if (proto == PROTO_TCP && (rec.state == TCP_TIME_WAIT_K || rec.state == TCP_NEW_SYN_RECV_K))
		return 0;

	ino = BPF_CORE_READ(sk, sk_socket, file, f_inode, i_ino);
	if (!ino)
		return 0;

	fam = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (fam == AF_INET_K) {
		__u32 s4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		__u32 d4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		__builtin_memcpy(rec.src, &s4, 4);
		__builtin_memcpy(rec.dst, &d4, 4);
		rec.family = 4;
	} else if (fam == AF_INET6_K) {
		BPF_CORE_READ_INTO(&rec.src, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(&rec.dst, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
		rec.family = 6;
	} else {
		return 0;
	}

	rec.ino = ino;
	rec.uid = uid;
	rec.proto = proto;
	rec.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	rec.dport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));

	bpf_seq_write(seq, &rec, sizeof(rec));
	return 0;
}

SEC("iter/tcp")
int dump_tcp(struct bpf_iter__tcp *ctx)
{
	struct sock_common *skc = ctx->sk_common;
	__u8 st;

	if (!skc)
		return 0;
	st = BPF_CORE_READ(skc, skc_state);
	if (st == TCP_TIME_WAIT_K || st == TCP_NEW_SYN_RECV_K)
		return 0;
	return emit_sock(ctx->meta->seq, (struct sock *)skc, PROTO_TCP, ctx->uid);
}

SEC("iter/udp")
int dump_udp(struct bpf_iter__udp *ctx)
{
	struct udp_sock *up = ctx->udp_sk;

	if (!up)
		return 0;
	return emit_sock(ctx->meta->seq, (struct sock *)up, PROTO_UDP, ctx->uid);
}
