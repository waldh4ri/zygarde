# Cell reference

Cells run in the order below (`allCells` in `cmd/zygarde/main.go`). Select some with `--cells id1,id2`; `--list` prints the IDs. "Timeout" is the Cell's own budget; the supervisor adds 10 seconds before killing the worker.

| # | ID | Detects | Timeout | Needs |
|---|----|---------|---------|-------|
| 1 | [`ebpf_integrity`](#ebpf_integrity) | `bpf()` being filtered or blocked | 15 s | `CAP_BPF`/`CAP_SYS_ADMIN` |
| 2 | [`altered_syscall_table`](#altered_syscall_table) | rewritten `sys_call_table` entries | 15 s | x86_64, `CONFIG_KALLSYMS_ALL`, a kernel that dispatches through the table |
| 3 | [`hook_inventory`](#hook_inventory) | ftrace and kprobe hooks | 30 s | dynamic ftrace, tracefs |
| 4 | [`inline_hook`](#inline_hook) | patched function prologues | 15 s | x86_64, Linux 5.2+ |
| 5 | [`kernel_pointers`](#kernel_pointers) | swapped function pointers in `/proc`, `/sys` and VFS tables | 30 s | BTF, Linux 5.8+ |
| 6 | [`hidden_kernel_module`](#hidden_kernel_module) | unlinked modules, boot persistence | 15 s | - |
| 7 | [`kernel_taint`](#kernel_taint) | taint without a visible module | 15 s | - |
| 8 | [`hidden_process`](#hidden_process) | processes hidden from `/proc`, disguised processes | 30 s | BTF, Linux 5.8+ |
| 9 | [`hidden_file`](#hidden_file) | directory entries filtered from `getdents64` | 60 s | BTF, Linux 5.8+ |
| 10 | [`hidden_ebpf_program`](#hidden_ebpf_program) | hidden or dangerous eBPF programs | 30 s | BTF, Linux 5.9+ |
| 11 | [`hidden_socket`](#hidden_socket) | sockets hidden from `netstat`/`ss`, packet sniffers | 30 s | - (iterators and owners: BTF, Linux 5.8+) |
| 12 | [`netfilter_hooks`](#netfilter_hooks) | magic-packet netfilter hooks | 30 s | BTF, Linux 5.8+, netfilter |
| 13 | [`userspace_hooks`](#userspace_hooks) | `LD_PRELOAD`-style hooks, trojaned libraries | 30 s | - |

Each Cell either compares two views (kernel vs userspace) or checks an invariant. The tables show both views; "-" means there is no second view.

---

## ebpf_integrity

Verifies that `bpf()` tells the truth. It runs first because the other eBPF Cells depend on it.

- **Kernel view**: a randomly named canary program and map that Zygarde loads itself.
- **Userspace view**: `BPF_PROG_GET_NEXT_ID`, `BPF_MAP_GET_NEXT_ID`, `BPF_PROG_GET_FD_BY_ID`.
- **SUSPICIOUS when**: the canary program or map is missing from enumeration, or `GET_FD_BY_ID` fails for it. Also, any Cell's `bpf()` permission error is classified as SUSPICIOUS when the environment says it should work (see [Architecture](architecture.md#the-cell-contract)).

## altered_syscall_table

- **Kernel view**: `sys_call_table` entries, read with a kprobe.
- **Userspace view**: the handler addresses in `/proc/kallsyms`.
- **Needs**: x86_64, `CONFIG_KALLSYMS_ALL` (the table is a data symbol), readable addresses (`kptr_restrict`).
- **Skips** on kernels that no longer dispatch syscalls through the table: since Linux 6.9, and backported to 6.8.5, 6.6.26, 6.1.85 and 5.15.154, x86_64 uses a `switch` in `x64_sys_call()`, so hooking the table has no effect. `hook_inventory` and `inline_hook` cover how syscalls are hooked there. Not backported to 5.10 and 5.4; RHEL 9's 5.14 still uses the table.
- **SUSPICIOUS when**: an entry points somewhere other than the function `/proc/kallsyms` names for it.

## hook_inventory

Inventories every ftrace and kprobe hook and attributes each to its owner.

- **Kernel view**: ftrace `enabled_functions` and `kprobes/list`.
- **Userspace view**: none; instead the owner of each handler is attributed to the kernel, a visible module, a BPF program, or per-function livepatch (`/sys/kernel/livepatch`).
- **Needs**: dynamic ftrace and tracefs. If tracefs is not mounted it is mounted in the worker's private mount namespace and cannot outlive it.
- **SUSPICIOUS when**:
  - an ftrace callback sets `FTRACE_OPS_FL_IPMODIFY` (flag `I`, able to redirect execution) and is not livepatch. Before Linux 6.0 ftrace also set that flag on `direct_ops` for every BPF trampoline, so a lone direct call into a `bpf_trampoline_*` is not counted as a redirection;
  - a handler resolves to no symbol, meaning code outside the kernel, visible modules and named BPF programs.
- **Observations**: BPF trampolines, kprobes, livepatch and other legitimate hooks.
- **Canary**: its own fentry (or kprobe) hook must appear in `enabled_functions`.

## inline_hook

Detects rootkits that patch the first instructions of a function (Reptile-family via khook, Mélofée), which bypasses ftrace and kprobes and so is invisible to `hook_inventory`.

- **Kernel view**: the first 24 bytes of syscall dispatchers and handlers and of VFS, `/proc` and `/proc/net` functions, including the instructions after the ftrace NOP.
- **Expected**: on x86_64 the kernel only places an `endbr64` (sealed to a different encoding by IBT: `66 0f 1f 00` or `0f 1f 40 d6`) and a 5-byte ftrace site: a NOP, or a call to ftrace or one of its trampolines. These are cross-checked with `enabled_functions` and `available_filter_functions`.
- **SUSPICIOUS when**: a jump leaves the kernel text (at or right after the ftrace NOP), the ftrace site is overwritten, or a call is not accounted for by `enabled_functions`.
- **Canary**: a kprobe on `getuid` is planted and its patch must be seen when that function is read.
- Needs `const volatile` (`.rodata`) support in BPF maps, so it is SKIPPED on 4.19.

## kernel_pointers

Detects a swapped pointer in an operations table while the code itself is untouched: `iterate_shared` of `/proc` (adore-ng), the `show` of `/proc/net/tcp`'s `seq_operations` (Snapekit, VoidLink), the `seq_operations` of `/proc/modules`.

- **Kernel view**: Zygarde opens `/proc`, `/proc/net/*`, `/proc/modules`, `/proc/kallsyms`, `/sys/module` and system directories **without reading them**; a BPF task-file iterator then reads, from each `struct file`, its `file_operations`, `inode_operations`, the `seq_file`'s operations (recognised by `seq_file->file` pointing back at the file) and, for procfs, the `proc_dir_entry`'s `proc_ops` and `seq_ops`.
- **Userspace view**: the owner of each pointer, from `/proc/kallsyms`, `/proc/modules` and `/proc/vmallocinfo`, plus the table addresses `/proc/kallsyms` gives.
- **Rule**: every pointer must belong to the kernel or to the module that implements the file (the filesystem's module, via `super_block->s_type->owner`, or the protocol's: `ipv6`, `unix`, `af_packet`).
- **SUSPICIOUS when**: a pointer is in code no visible module owns; it belongs to an unrelated module; a table sits outside kernel and module memory (a copied table; `single_open()`'s own heap table is expected); a function pointer does not start a function `kallsyms` names; or the tables are not where `/proc/kallsyms` says they are, which means `/proc/kallsyms` is being filtered (Singularity sanitises it).
- **Canaries**: all descriptors Zygarde opened are visible to the iterator; Zygarde's own `/proc/net/tcp` show function reads back as `tcp4_seq_show`.

## hidden_kernel_module

Two parts.

**Hidden loaded modules**
- **Kernel view**: module kobjects in `/sys/module` and module BTF.
- **Userspace view**: the module list in `/proc/modules` (what `lsmod` shows).
- Rootkits unlink themselves from the module list (`list_del`) or delete their kobject (`kobject_del`). Only loadable modules have `/sys/module/<name>/initstate`, which separates them from built-ins.
- Note: the `iter/ksym` iterator walks the same `modules` list as `/proc/modules`, so it would not reveal a `list_del`-hidden module and is not used for this.
- **Third view, for modules that remove themselves from both** `/proc/modules` and `/sys/module` (so those two agree): `/proc/vmallocinfo` names the allocator of every vmalloc area, and the module loader makes one allocation per module (`load_module`, `layout_and_allocate` or `move_module`, by kernel). More such allocations than modules listed, still true 300 ms later, is SUSPICIOUS. Only before Linux 6.4: from then a module has one allocation per memory type and 7.0 uses a shared cache, so those kernels record a limit.
- **Not read on purpose**: `/sys/module/*/sections/*`. Those files are backed by memory a rootkit can free while leaving the files in place (Diamorphine frees its module's section attributes), and reading one oopses the kernel. Module symbols and `/proc/modules` give the same ownership without them.

**Boot persistence**
- Lists modules configured to load at boot: `modules-load.d`, `/etc/modules`, `modprobe.d`, systemd units, udev rules, and `insmod`/`modprobe` lines in `rc.local`, `rc.modules` and shell profiles.
- **SUSPICIOUS when**: an `insmod` targets a file outside `/lib/modules/$(uname -r)` (Mélofée loads `/etc/intel_audio/intel_audio.ko` from `rc.modules`); an `install`/`remove` directive runs arbitrary commands or command substitutions; a configuration file is hidden from its own directory listing; a file cannot be parsed completely.
- Module names themselves are observations: `modprobe` only searches the running kernel's tree, so a name missing from it cannot load.

## kernel_taint

- **Kernel view**: kernel taint flags, `/proc/sys/kernel/tainted`.
- **Userspace view**: per-module taint, `/sys/module/*/taint`.
- Loading a module taints the kernel (out-of-tree `O`, unsigned `E`, ...) until reboot. Module-attributable flags are `P F C O E K N`.
- **SUSPICIOUS when**: a module taint is set that no visible module carries: a module hid itself, or was loaded and later unloaded.
- **Kernel oopses**: the kernel log (`/dev/kmsg`) is searched for oopses, BUGs and panics, and the `D` taint with no oops left in the log is reported too. A healthy kernel does not oops because a process reads sysfs or procfs files, so one that did points to a rootkit that left kernel objects dangling (Diamorphine frees its module's section attributes). Oopses that happen *while Zygarde runs* are attributed in the failed Cell's result, with the faulting function, the call trace and the files the worker was reading.

## hidden_process

- **Kernel view**: three independent sources, taken before and after reading `/proc`: the BPF `iter/task` iterator (every thread), the `init_task.tasks` walk through the open-coded `bpf_iter_task_new` kfunc (Linux 6.7+), and `sched_switch` sampling.
- **Userspace view**: `/proc` process listing and `/proc/<pid>/task` thread listings.
- PIDs are translated into Zygarde's PID namespace (so it works inside containers) and matched by `start_time`, so PIDs reused mid-scan do not count.
- **SUSPICIOUS when**:
  - a task exists in the kernel but not in `/proc`;
  - a process is named like a kernel thread (`kworker/...`, or a `[bracketed]` name or command line) but is not flagged `PF_KTHREAD`;
  - a process runs from a `memfd` or a deleted binary in a temporary, memory-backed or hidden directory (any user), or any root process runs from `/dev/shm`, `/tmp`, a hidden directory or a non-packaged deleted binary. This is confirmed against a fresh snapshot after reading `/proc`. `/run` (tmpfs) is covered too, where BPFDoor variants copy themselves.
  - an empty directory (or anything else) is mounted over `/proc/<pid>` or something below it. The PID stays in the /proc listing, so the comparison above does not notice, but every tool reading `/proc/<pid>/*` sees nothing. Rootkits then restore `/etc/mtab` to hide the mount. Three views of the mounts are compared: the kernel's mount tree (second BPF `iter/task` program, once per mount namespace, walking `mount->mnt_mounts` and recording what each mount covers inside procfs), `/proc/<pid>/mountinfo` of a process in each namespace, and the device number of every `/proc/<pid>` (a mounted-over entry is on another device than `/proc`). Any one of them is enough; the finding lists which saw it, whether `/etc/mtab` is a symlink or a regular file that omits the mount, and what was mounted.
  - the kernel's mount tree has a mount that the fullest `/proc/<pid>/mountinfo` of its namespace omits (only mounts below that reader's root directory are compared, so systemd sandboxes and containers do not count), or a namespace's mount count does not match the mounts reachable in its tree.
  - Command lines padded with long runs of blanks are observations.
- `--preserve-dir` saves copies of the volatile binaries (deleted or memfd).
- **Canaries**: a child process planted by Zygarde must appear in the BPF iterator, `/proc`, and the `init_task` walk; Zygarde itself must appear in `sched_switch` sampling.

## hidden_file

- **Kernel view**: what the filesystem produced, recorded by a kprobe on `filldir64`.
- **Userspace view**: what `getdents64` returned.
- Scope: sensitive directories (binaries, libraries, persistence locations, `/tmp`, `/dev/shm`, home directories), `/proc` and `/sys/module`.
- Directories are read in batches so the ring buffer never overflows; lost events become a limitation. Directories on network or FUSE filesystems are skipped with a limitation, since an unreachable server would stall the scan.
- **SUSPICIOUS when** an entry the filesystem produced is not returned to userspace; or, in system directories, on dot-entries:
  - `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/lib*`, `/usr/lib*` hold no dot-entries on a stock install (exceptions: `.build-id`, FIPS `.hmac` files, Gentoo `.keep*`). Others are observations, and SUSPICIOUS when they hold executables (Scales keeps a trojaned `sudo` in `/usr/bin/.local`), sit in a binary directory even without an executable, or are writable by anyone (HiddenWasp keeps the path of its library in `/usr/sbin/.ifup-local`). Small text files are quoted.
- **Canary**: a file Zygarde creates must be produced by the filesystem and returned by `getdents64`.

## hidden_ebpf_program

Detects hidden eBPF programs and eBPF rootkits (LinkPro, Scales) that attach to syscall tracepoints, which do not go through ftrace.

- **Kernel view**: BPF program iterator (including `tag`, `loaded_at`, `uid`), Zygarde's own `bpf()` calls traced at syscall exit, and the holders of every program and link read from every task's file table.
- **Userspace view**: `BPF_PROG_GET_NEXT_ID` and `/sys/fs/bpf` pins.
- **Attachment inventory**: where every program is attached, from BPF links (`BPF_LINK_GET_NEXT_ID`), BPF-running perf events (`BPF_TASK_FD_QUERY`), legacy `BPF_PROG_ATTACH` cgroups (`BPF_PROG_QUERY`), `prog_array` tail-call maps, and interfaces (XDP and tc filters over netlink).
- **SUSPICIOUS when**:
  - a program is in the kernel but not enumerable by `BPF_PROG_GET_NEXT_ID`;
  - a program is held only by processes hidden from `/proc`;
  - a program on a sensitive attach point (directory listing, `bpf()`, `kill`, `ptrace`, raw `sys_enter`/`sys_exit`) can rewrite user memory (`bpf_probe_write_user`) or override return values (audited by resolving helper calls in the translated instructions);
  - an XDP or tc program is hidden or unnamed.
- **Canaries**: its own program is visible to the iterator and to enumeration; its `bpf()` calls are all seen; a `bpf_seq_write` call is found in the translated instructions; the program is held by Zygarde in the file-table iterator.
- Lockdown `confidentiality` skips it (see [Compatibility](compatibility.md#kernel-lockdown)).

## hidden_socket

- **Kernel view**: BPF `iter/tcp` and `iter/udp`, netlink `sock_diag` (what `ss` uses), and every socket FD across task file tables (including `AF_PACKET`, `SOCK_RAW` and child network namespaces).
- **Userspace view**: `/proc/net/{tcp,udp,raw}{,6}` and `/proc/net/packet` (what `netstat` uses).
- **SUSPICIOUS when**:
  - a socket is missing from a view across three reads, confirmed by exact `sock_diag` lookups;
  - an `AF_PACKET` sniffer is hidden from `/proc/net/packet`;
  - a socket is held only by processes hidden from `/proc`;
  - a raw `AF_PACKET` socket reads IP traffic (`ETH_P_ALL`/`IP`/`IPV6`), or a raw IP socket (ICMP, TCP, ...) is held by a program that is not a recognised network tool installed in a system directory. This is how BPFDoor and Prism wait for a trigger packet without a port. The classic BPF filter is read through packet `sock_diag` and its constants (magic values, ports) are reported.
- Kernels built without `CONFIG_INET_DIAG` (the upstream CI kernels) cannot dump `sock_diag`: the Cell keeps the `/proc/net` view and skips only that comparison.
- **Canaries**: sockets Zygarde opens must show up in `/proc/net`, `sock_diag`, the BPF iterator and the file-table holders view.

## netfilter_hooks

Kernel backdoors listen for "magic packets" from a netfilter hook, which sees every packet before any socket (Reptile, Diamorphine variants, Syslogk, FontOnLake, VoidLink).

- **Kernel view**: `nf_hook_entries` of every hook point and of the first 32 network devices (ingress/egress), for every network namespace a task lives in (IPv4, IPv6, ARP, bridge), read from `struct net` by a BPF task iterator.
- **Userspace view**: none; each hook function is attributed to its owner as for `kernel_pointers`.
- **Observations**: the kernel, visible modules (conntrack, iptables, nftables, bridge) and BPF netfilter links.
- **SUSPICIOUS when**: a hook function is owned by no visible module.
- **Canaries**: Zygarde's own network namespace is seen; on Linux 6.4+ a do-nothing BPF netfilter link on IPv4 `LOCAL_OUT` is planted and must be read back.
- Limitation: network namespaces no task lives in (only pinned in `/run/netns`) are not covered.

## userspace_hooks

- **Kernel view**: none. Zygarde does not use libc, so these hooks cannot fool it; this Cell reports them because they still fool every other tool.
- **Userspace view**: `/etc/ld.so.preload`, `ld.so.conf`, `/etc/ld.so.cache`, `LD_PRELOAD`/`LD_AUDIT`, resolved **inside each process's root** (`openat2` with `RESOLVE_IN_ROOT`), and injected libraries in `/proc/<pid>/maps`.
- **SUSPICIOUS when**:
  - `/etc/ld.so.preload` has entries;
  - `ld.so.conf` or `ld.so.cache` point into `/tmp`, `/dev/shm`, hidden or world-writable directories;
  - preloaded libraries are missing or hidden;
  - an executable shared object is mapped from a temporary, memory-backed or hidden path;
  - a shared library mapped from a system directory does not match the checksums of the package that installed it (dpkg `.md5sums`, or the SQLite rpm database, which Zygarde parses itself including its write-ahead log). A library replaced in place, as Ebury does to `libkeyutils`, is caught this way.
  - a shared library mapped from a system directory, or a PAM module (`security/*.so`) present in one, belongs to no installed package (dpkg `.list` files, or the rpm database). This catches implants that add a library next to the legitimate ones, such as a backdoor PAM module, instead of replacing one. Software installed outside the package manager (vendor GPU drivers, JDK tarballs) shows up here too.
- Limitations: processes in other mount namespaces are skipped; Berkeley DB rpm databases (RHEL 8) are not covered.
