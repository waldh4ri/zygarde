# Compatibility

## Baseline

- Linux, x86_64 or arm64, root privileges (see [Getting started](getting-started.md#requirements)).
- Linux 5.8+ with BTF (`CONFIG_DEBUG_INFO_BTF=y`) for most Cells.
- Cells probe for the kernel features they need, checking BTF **types** rather than version numbers so distribution backports are honoured, and report SKIPPED with a reason when something is missing. `--btf <file>` supplies external BTF for kernels without `/sys/kernel/btf/vmlinux`.

## Per-Cell kernel requirements

| Cell | Needs |
|------|-------|
| `ebpf_integrity` | `bpf()` |
| `altered_syscall_table` | x86_64; `CONFIG_KALLSYMS_ALL`; readable `/proc/kallsyms`; a kernel that still dispatches via `sys_call_table` (before 6.9, or not yet backported: 6.8.5, 6.6.26, 6.1.85, 5.15.154) |
| `hook_inventory` | dynamic ftrace, tracefs (mounted privately if needed), not lockdown |
| `inline_hook` | x86_64; Linux 5.2+ (read-only data maps); BTF |
| `kernel_pointers` | BTF; `iter/task_file`, Linux 5.8+ |
| `hidden_kernel_module` | none |
| `kernel_taint` | none |
| `hidden_process` | BTF; `iter/task`, Linux 5.8+ (`init_task.tasks` walk needs 6.7+, else skipped as a limitation; the mount-tree walk needs global BPF functions, 5.5+, and is a limitation if the verifier rejects it) |
| `hidden_file` | BTF; Linux 5.8+ |
| `hidden_ebpf_program` | BTF; `iter/bpf_prog`, Linux 5.9+ |
| `hidden_socket` | none for the `/proc/net` and `sock_diag` views; BTF and Linux 5.8+ for the iterators and ownership check |
| `netfilter_hooks` | BTF; Linux 5.8+; netfilter. The canary BPF netfilter link needs 6.4+ |
| `userspace_hooks` | none |
| `orphan_namespace` | BTF; `iter/task` and `iter/task_file`, Linux 5.8+. Entering a network namespace held only by a socket needs `pidfd_getfd` (5.6+), otherwise its contents are not listed |

Kernel facts behind these, verified from source and the VM matrix:

- `iter/task` since 5.8, `iter/bpf_prog` since 5.9.
- Kernels before 5.11 charge BPF memory to `RLIMIT_MEMLOCK`; Zygarde lifts it, and reports the problem if it cannot.
- `bpf_get_ns_current_pid_tgid()` needs Linux 5.7. Without it Zygarde must be in the initial PID namespace (Ubuntu 20.04's 5.4 lacks it).
- Kernels before 5.2 cannot load programs with `.rodata` maps (4.19): `inline_hook` is SKIPPED there.
- The 5.10 verifier rejects some bounded loops, so loops are unrolled in the BPF sources.
- On 5.10, a TCP listener's `socket->file` reads NULL from `iter/tcp`; the socket inode is read through `socket_alloc.vfs_inode` instead.
- Redhat kernels backport: Rocky 8 (4.18) has the task and prog iterators and ring buffers; Rocky 9 (5.14) did not get the `x64_sys_call()` change, so the syscall table Cell runs there.

## Kernel lockdown

| Mode | Effect |
|------|--------|
| `none`, `integrity` (the usual Secure Boot default) | no effect |
| `confidentiality` | BPF may not read kernel memory. Skipped: `altered_syscall_table`, `inline_hook`, `kernel_pointers`, `netfilter_hooks`, `hidden_process`, `hidden_file` (all read kernel memory), and `hook_inventory` (tracefs locked). `hidden_ebpf_program` is skipped too: it only reads user memory, which lockdown allows, but cilium/ebpf detects helper support by probing `bpf_probe_read_kernel()`, is denied, and downgrades `bpf_probe_read_user()` to the legacy `bpf_probe_read()`, which lockdown forbids. `hidden_socket` runs without its ownership check. `ebpf_integrity`, `hidden_kernel_module`, `kernel_taint` and `userspace_hooks` still run |

The report header shows the lockdown mode; Coverage lists what it excluded.

## Other environment effects

- **`kernel.kptr_restrict`** (and missing privileges): when `/proc/kallsyms` reports zero addresses, Cells that need symbols report SKIPPED ("kernel symbols unavailable"), with the reason read from the sysctl.
- **No tracefs** (containers): syscall tracing uses `tp_btf` and works; `hook_inventory` mounts tracefs privately when possible.
- **Containers**: need `--privileged` (and `--pid=host` to see the host). Cells translate PIDs, so they also work inside a PID namespace.
- **SELinux / AppArmor**: a confined profile can deny `bpf()`; that is reported (see [Architecture](architecture.md#the-cell-contract)).
- **rpm databases**: SQLite (Fedora, RHEL 9+) is supported; Berkeley DB (RHEL 8) is not. dpkg is supported.
- **arm64**: build- and VM-tested. Cells that need x86 instruction decoding (`altered_syscall_table`, `inline_hook`) do not run.

## Verified in VMs (no false positives)

- Upstream kernels: 4.19, 5.4, 5.10, 5.15, 6.1, 6.6, 6.12, 6.18, 7.2.
- Distributions: Ubuntu 20.04 to 26.04, Debian 11 to 13, Rocky 8 to 10, Fedora 44, Amazon Linux 2023, openSUSE Leap 15.6 and 16.0.
- arm64 (emulated): Debian 12 and 13, Ubuntu 22.04 and 24.04, Rocky 9, Fedora 44.
- Kernel lockdown in `integrity` and `confidentiality` modes.
- Detections firing on planted stand-ins: Debian 12, Ubuntu 24.04, Debian 13 (see [Testing](testing.md#fixtures-detections-must-fire)).

The authoritative list is `test/vm/distros.txt` and the kernel list in `test/vm/upstream.sh`.
