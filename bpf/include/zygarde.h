/* Shared helpers for Zygarde's BPF programs. */
#ifndef __ZYGARDE_H__
#define __ZYGARDE_H__

#include "bpf_core_read.h"

/* Native syscall numbers, as seen by the raw sys_enter/sys_exit tracepoints
 * (arch/x86/entry/syscalls/syscall_64.tbl, scripts/syscall.tbl).
 * 32-bit compat syscalls use other numbers and are not covered.
 */
#if defined(__TARGET_ARCH_x86)
#define NR_open     2
#define NR_execve   59
#define NR_openat   257
#define NR_bpf      321
#define NR_execveat 322
#define NR_openat2  437
#elif defined(__TARGET_ARCH_arm64)
#define NR_open     -1 /* no open(2) on arm64 */
#define NR_execve   221
#define NR_openat   56
#define NR_bpf      280
#define NR_execveat 281
#define NR_openat2  437
#endif

/* Identify zygarde's own process. Set by userspace before loading
 * (bpfutil.SetTarget): zygarde's PID namespace device/inode and its PID in
 * that namespace. bpf_get_current_pid_tgid() returns init-namespace numbers,
 * which differ from getpid() inside containers.
 */
const volatile __u64 pidns_dev = 0;
const volatile __u64 pidns_ino = 0;
const volatile __u32 target_tgid = 0;

static __always_inline bool is_target(void)
{
	/* bpf_get_ns_current_pid_tgid() exists since Linux 5.7. The CO-RE check
	 * becomes a constant at load time, so older kernels never see the call.
	 */
	if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_ns_current_pid_tgid)) {
		struct bpf_pidns_info ns = {};

		if (bpf_get_ns_current_pid_tgid(pidns_dev, pidns_ino, &ns, sizeof(ns)))
			return false;
		return ns.tgid == target_tgid;
	}
	/* Older kernels: init-namespace numbers, only valid when zygarde runs in
	 * the initial PID namespace (bpfutil.SetTarget checks this).
	 */
	return (bpf_get_current_pid_tgid() >> 32) == target_tgid;
}

#endif /* __ZYGARDE_H__ */
