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
| 7 | [`usermode_helpers`](#usermode_helpers) | modprobe, core dump pipe and other programs the kernel runs as root, pointed elsewhere or hidden | 15 s | - (kernel-memory view: `CONFIG_KALLSYMS_ALL`) |
| 8 | [`kernel_taint`](#kernel_taint) | taint without a visible module | 15 s | - |
| 9 | [`hidden_process`](#hidden_process) | processes hidden from `/proc`, disguised processes, hidden or fileless tracers | 30 s | BTF (before 5.8: kernel symbols) |
| 10 | [`hidden_file`](#hidden_file) | directory entries filtered from `getdents64` | 60 s | BTF, Linux 5.8+ |
| 11 | [`hidden_ebpf_program`](#hidden_ebpf_program) | hidden or dangerous eBPF programs | 30 s | BTF, Linux 5.9+ |
| 12 | [`hidden_socket`](#hidden_socket) | sockets hidden from `netstat`/`ss`, packet sniffers | 30 s | - (iterators and owners: BTF, Linux 5.8+) |
| 13 | [`netfilter_hooks`](#netfilter_hooks) | magic-packet netfilter hooks | 30 s | BTF, Linux 5.8+, netfilter |
| 14 | [`userspace_hooks`](#userspace_hooks) | `LD_PRELOAD`-style hooks, trojaned libraries, mappings hidden from `maps`, in-memory ELF images | 30 s | - (mapping comparison: BTF, Linux 5.12+) |
| 15 | [`orphan_namespace`](#orphan_namespace) | namespaces without a process that hold listeners, mounts or devices | 30 s | BTF, Linux 5.8+ |

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
- **Kernel memory views** of `struct module`, walked from userspace with offsets from BTF through a BPF kernel-memory reader (`internal/kmem`, a kprobe on `getuid` using `bpf_probe_read_kernel()`, which cannot fault on freed memory):
  - the module list (`modules`), which `/proc/modules` prints;
  - `module_kset`, the kobjects behind `/sys/module`, each pointing to its `struct module`;
  - `mod_tree`, the latched tree the kernel searches to map an address to its module (exception tables, kallsyms, stack traces). A module that unlinks itself from the list **and** deletes its kobject, so `/proc/modules` and `/sys/module` agree, is still there.
  - Each walk must find every module userspace shows, or it is not trusted for this scan (a limit).
- **SUSPICIOUS when** (confirmed by a second read 300 ms later; modules loading or unloading are skipped):
  - a live module is in `mod_tree` or `module_kset` but not on the module list, naming the module;
  - a live module is on the module list but `/proc/modules` leaves it out (filtered output);
  - a module's `/sys/module/<name>/sections` (or `notes`) directory lists files while its `sect_attrs` (`notes_attrs`) is NULL, or points to memory that no longer holds the `sections` attribute group or names other sections. Diamorphine frees its section attributes this way, and reading those files oopses the kernel; only the directory is listed.
- **Fallback when kernel memory cannot be read** (`kptr_restrict=2`, lockdown `confidentiality`, no `CONFIG_KALLSYMS_ALL`): `/proc/vmallocinfo` names the allocator of every vmalloc area, and before Linux 6.4 the module loader makes one allocation per module (`load_module`, `layout_and_allocate` or `move_module`, by kernel). More such allocations than modules listed, still true 300 ms later, is SUSPICIOUS. From 6.4 a module has one allocation per memory type (7.0 uses a shared cache), and older kernels with a backported `struct module_memory` in their BTF (RHEL 9.8's 5.14) behave the same, so there the fallback records a limit.
- **Not read on purpose**: the files in `/sys/module/*/sections/`, for the reason above. Module symbols and `/proc/modules` give the same ownership without them.

**Boot persistence**
- Lists modules configured to load at boot: `modules-load.d`, `/etc/modules`, `modprobe.d`, systemd units, udev rules, and `insmod`/`modprobe` lines in `rc.local`, `rc.modules` and shell profiles.
- **SUSPICIOUS when**: an `insmod` targets a file outside `/lib/modules/$(uname -r)` (Mélofée loads `/etc/intel_audio/intel_audio.ko` from `rc.modules`); an `install`/`remove` directive runs arbitrary commands or command substitutions; a configuration file is hidden from its own directory listing; a file cannot be parsed completely.
- Module names themselves are observations: `modprobe` only searches the running kernel's tree, so a name missing from it cannot load.

## usermode_helpers

The kernel itself starts some programs as root, outside any session: `modprobe` when something asks for a module that is not loaded (any user can trigger it with an unknown socket family or binary format), the core dump handler when `core_pattern` starts with `|` (any crashing process), the hotplug helper (`uevent_helper`), the orderly poweroff command, and the release agent of a cgroup v1 hierarchy. Pointing one of them at your own program gives root on demand and a persistence no crontab or service shows. It is a classic privilege escalation target (overwriting `modprobe_path` from a kernel exploit) and container escape (cgroup `release_agent`).

- **Kernel view**: `modprobe_path`, `core_pattern`, `uevent_helper` and `poweroff_cmd` read from kernel memory by a kprobe on `getuid` (addresses from `/proc/kallsyms`, checked to lie in the kernel image's data).
- **Userspace view**: `/proc/sys/kernel/{modprobe,core_pattern,poweroff_cmd}`, `/sys/kernel/uevent_helper`, and `release_agent` at the root of each mounted cgroup v1 hierarchy.
- **SUSPICIOUS when**:
  - procfs or sysfs shows another value than kernel memory, in two reads of both (the read is filtered to hide the real helper);
  - a helper program lives in a temporary, memory-backed (`/dev/shm`, `/run`) or hidden directory;
  - the program is hidden from its directory listing;
  - the program or one of its directories is owned by a user other than root, or writable by everyone or a non-root group (unless `/bin/sh` can be replaced the same way: then the whole system can, which is recorded as a limitation);
  - the program is in a system directory (`/usr`, `/bin`, `/sbin`, `/lib*`, not `/usr/local`) but belongs to no installed package (dpkg file lists or the SQLite rpm database; symlinks are resolved first, so a packaged `/sbin/modprobe` link pointing at a new file is caught).
- **Observations**: every helper and the program it runs (vendor crash handlers in `/opt` are listed, not flagged), and helpers naming a missing file.
- **Canary**: `linux_banner`, read with the helpers, must start with `Linux version `.
- Limitations: without `CONFIG_KALLSYMS_ALL` or with hidden addresses (`kptr_restrict`) only the userspace view is checked; the kernel runs helpers from init's root directory, so the files are not examined when zygarde runs in a container with another root.

## kernel_taint

- **Kernel view**: kernel taint flags, `/proc/sys/kernel/tainted`.
- **Userspace view**: per-module taint, `/sys/module/*/taint`.
- Loading a module taints the kernel (out-of-tree `O`, unsigned `E`, ...) until reboot. Module-attributable flags are `P F C O E K N`.
- **SUSPICIOUS when**: a module taint is set that no visible module carries: a module hid itself, or was loaded and later unloaded.
- **Kernel oopses**: the kernel log (`/dev/kmsg`) is searched for oopses, BUGs and panics, and the `D` taint with no oops left in the log is reported too. A healthy kernel does not oops because a process reads sysfs or procfs files, so one that did points to a rootkit that left kernel objects dangling (Diamorphine frees its module's section attributes). Oopses that happen *while Zygarde runs* are attributed in the failed Cell's result, with the faulting function, the call trace and the files the worker was reading.

## hidden_process

- **Kernel view**: three independent sources, taken before and after reading `/proc`: the BPF `iter/task` iterator (every thread), the `init_task.tasks` walk through the open-coded `bpf_iter_task_new` kfunc (Linux 6.7+), and `sched_switch` sampling.
- **Kernels without the task iterator (before 5.8)**: the tasks are read from kernel memory instead (`internal/ktask`), with offsets from BTF (the kernel's, or `--btf`/`--btfhub`), two independent ways: the global task list (`init_task.tasks`) and the process tree (every thread's `children` list, from `init_task`), each process's threads coming from `signal->thread_head`. No kernel enumeration code runs, so hooks on `getdents`, `/proc` readdir or the PID lookup don't hide anything from it. A process present on only one of the two structures, in both snapshots, is reported as unlinked from the other. The mount-tree check is skipped there (it needs the iterator). `ZYGARDE_TASK_VIEW=memory` forces this view on newer kernels, to compare both.
- **Userspace view**: `/proc` process listing and `/proc/<pid>/task` thread listings.
- PIDs are translated into Zygarde's PID namespace (so it works inside containers) and matched by `start_time`, so PIDs reused mid-scan do not count.
- **SUSPICIOUS when**:
  - a task exists in the kernel but not in `/proc`;
  - a process is named like a kernel thread (`kworker/...`, or a `[bracketed]` name or command line) but is not flagged `PF_KTHREAD`;
  - a process runs from a `memfd` or a deleted binary in a temporary, memory-backed or hidden directory (any user), or any root process runs from `/dev/shm`, `/tmp`, a hidden directory or a non-packaged deleted binary. This is confirmed against a fresh snapshot after reading `/proc`. `/run` (tmpfs) is covered too, where BPFDoor variants copy themselves.
  - an empty directory (or anything else) is mounted over `/proc/<pid>` or something below it. The PID stays in the /proc listing, so the comparison above does not notice, but every tool reading `/proc/<pid>/*` sees nothing. Rootkits then restore `/etc/mtab` to hide the mount. Three views of the mounts are compared: the kernel's mount tree (second BPF `iter/task` program, once per mount namespace, walking `mount->mnt_mounts` and recording what each mount covers inside procfs), `/proc/<pid>/mountinfo` of a process in each namespace, and the device number of every `/proc/<pid>` (a mounted-over entry is on another device than `/proc`). Any one of them is enough; the finding lists which saw it, whether `/etc/mtab` is a symlink or a regular file that omits the mount, and what was mounted.
  - the kernel's mount tree has a mount that the fullest `/proc/<pid>/mountinfo` of its namespace omits (only mounts below that reader's root directory are compared, so systemd sandboxes and containers do not count), or a namespace's mount count does not match the mounts reachable in its tree.
  - a process is traced (ptrace: the kernel's `PT_PTRACED`, with the tracer as the task's parent) and `TracerPid` in `/proc/<pid>/task/<tid>/status` shows another tracer or none: something filters `/proc` to hide an injection in progress;
  - the tracer runs from a memfd, a temporary or memory-backed directory, a deleted file outside system directories, or (root tracers only) a hidden directory: an injector covering its tracks. IDE debuggers live in hidden directories of their user's home, hence the root condition. Other traces (gdb, strace) are observations. Traces are confirmed in three kernel snapshots.
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
- **Userspace view**: `BPF_PROG_GET_NEXT_ID` and the pins of every BPF filesystem: each one mounted in zygarde's mount namespace and in the mount namespace of any running process (read through `/proc/<pid>/root`), wherever it is mounted.
- **Attachment inventory**: where every program is attached, from BPF links (`BPF_LINK_GET_NEXT_ID`), BPF-running perf events (`BPF_TASK_FD_QUERY`), legacy `BPF_PROG_ATTACH` cgroups (`BPF_PROG_QUERY`), sk_msg and sk_skb programs attached to sockmaps and sockhashes (`BPF_PROG_QUERY` on the map, Linux 6.0+), `prog_array` tail-call maps, and interfaces (XDP and tc filters over netlink).
- **SUSPICIOUS when**:
  - a program is in the kernel but not enumerable by `BPF_PROG_GET_NEXT_ID`;
  - a program is held only by processes hidden from `/proc`;
  - a program on a sensitive attach point (directory listing, `bpf()`, `kill`, `ptrace`, raw `sys_enter`/`sys_exit`) can rewrite user memory (`bpf_probe_write_user`) or override return values (audited by resolving helper calls in the translated instructions);
  - an XDP, tc or sockmap verdict program (all see traffic) is hidden or unnamed;
  - BPF objects are pinned in a BPF filesystem mounted in a temporary, memory-backed or hidden directory (a pin keeps a rootkit loaded after its loader exits; tools mount the filesystem at `/sys/fs/bpf`).
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
- Limitation: network namespaces no task lives in (only pinned in `/run/netns`, or held by a socket) are not covered here; `orphan_namespace` reports them and lists their contents.

## userspace_hooks

- **Kernel view**: the executable file-backed mappings of every process, from the kernel's VMA tree (`iter/task_vma`, Linux 5.12+). The linker hooks themselves need no kernel view: Zygarde does not use libc, so they cannot fool it; this Cell reports them because they still fool every other tool.
- **Userspace view**: `/proc/<pid>/maps`, `/etc/ld.so.preload`, `ld.so.conf`, `/etc/ld.so.cache`, `LD_PRELOAD`/`LD_AUDIT`, resolved **inside each process's root** (`openat2` with `RESOLVE_IN_ROOT`), and injected libraries in `/proc/<pid>/maps`.
- **SUSPICIOUS when**:
  - `/etc/ld.so.preload` has entries;
  - `ld.so.conf` or `ld.so.cache` point into `/tmp`, `/dev/shm`, hidden or world-writable directories;
  - preloaded libraries are missing or hidden;
  - an executable shared object is mapped from a temporary, memory-backed or hidden path;
    - Exception: Java runtimes unpack native libraries (JNA, jansi, netty, sqlite-jdbc) to temporary or cache directories and often delete them. A mapping is let through (and recorded as an observation) only when the process is verified as a JVM and the file looks like one the JVM extracted. The process must have a non-deleted `bin/java` that cannot be modified by group or others, is the JDK launcher (needs `libjli.so`), and maps `<home>/lib/**/server/libjvm.so`, an unmodifiable ELF exporting `JNI_CreateJavaVM`, from a directory with a JDK runtime image (`release`, `lib/modules` or `rt.jar`); the library must be an ELF shared object owned by the process's user, not writable by others, with a Java-generated name (a long random number or a 16-digit hexadecimal id). A process merely named `java`, or an executable library with another name, is still reported. memfd mappings are never excused.
  - a shared library mapped from a system directory does not match the checksums of the package that installed it (dpkg `.md5sums`, or the SQLite rpm database, which Zygarde parses itself including its write-ahead log). A library replaced in place, as Ebury does to `libkeyutils`, is caught this way.
  - a shared library mapped from a system directory, or a PAM module (`security/*.so`) or NSS module (`libnss_*.so*`, loaded by name from `nsswitch.conf`) present in one, belongs to no installed package (dpkg `.list` files, or the rpm database). This catches implants that add a library next to the legitimate ones, such as a backdoor PAM or NSS module, instead of replacing one. Software installed outside the package manager (vendor GPU drivers, JDK tarballs) shows up here too. PAM and NSS modules are also verified against their package checksums when no process has them mapped.
  - an executable file-backed mapping in the kernel's VMA tree, seen in three snapshots, is missing from `/proc/<pid>/maps` read twice in between: maps is filtered to hide an injected library. The file is named from `/proc/<pid>/map_files`. Anonymous code is not compared: JIT compilers flip it between writable and executable, so `maps` can legitimately differ for a moment.
  - an ELF header (`\x7fELF`) starts an anonymous executable mapping, or the anonymous mapping right before one (read through `/proc/<pid>/mem`): a program copied into memory and run from there by an in-memory ("userland exec") loader. `[vdso]` and JIT code never look like this; UPX-packed programs do.
  - a setuid or setgid ELF program in a binary or library directory has an RPATH or RUNPATH entry that an unprivileged user can fill: empty or relative (the current directory), in a temporary, memory-backed, hidden or world-writable directory, or a directory (or a missing one's closest parent) owned or writable by a user other than root. The linker ignores `LD_LIBRARY_PATH` for these programs but honours their own search path, so this is a planted root backdoor. `$ORIGIN` is expanded to the program's directory. A writable directory is only reported when the program itself cannot be replaced by the same user (otherwise the search path adds nothing).
- Limitations: processes in other mount namespaces are skipped by the package checks; Berkeley DB rpm databases (RHEL 8) are not covered.

## orphan_namespace

Finds namespaces that no process belongs to but that something else keeps alive, and says what is inside.

A namespace outlives its last process when a bind mount of its nsfs file (what `ip netns add` does), an open descriptor of it, or a socket created in it still references it. Every check that starts from a process never reaches it: `ps`, `ss`, `netstat`, `/proc/net`, `mountinfo` and the other Cells' task-based views. A listener, a stash of files, a network device or firewall rules can live there while the process that uses them is elsewhere or gone.

- **Kernel view**: the namespaces of every thread, read from the kernel's task list by a BPF `iter/task` program (mount, network, PID, IPC, UTS, user, cgroup and time namespaces, plus the namespaces a process will give its children), and the network namespace of every socket, read from every task's file table (`iter/task_file`, the same iterator `hidden_socket` uses for ownership).
- **Userspace view**: `nsfs` entries in the `mountinfo` of each mount namespace (bind mounts of namespace files).
- **Descriptors** that refer to a namespace file are read from the kernel too: the file iterator learns the `file_operations` of namespace files from Zygarde's own `/proc/self/ns/net` descriptor and records the namespace inode of every such descriptor. Unlike `/proc/<pid>/fd`, that covers processes hidden from `/proc`, and descriptors opened through a bind mount of the namespace file (whose link reads `/`, not `net:[inum]`). The type of the namespace comes from the descriptor itself (`pidfd_getfd` and `NS_GET_NSTYPE`, Linux 5.6+; older kernels fall back to the descriptor's link).
- A namespace is an **orphan** when it is pinned or holds a socket and has no member, and no namespace with a member needs it. A user namespace that owns a live namespace, and the parents of user and PID namespaces, are alive for that reason and are not reported. An orphan has to be seen twice, 400 ms apart, so a process exiting is not reported.
- **Contents**: each orphan is entered on a throwaway thread (`setns`, never returned from, so no other thread is affected) that only reads `/proc` files the kernel renders for that namespace.
  - network: interfaces, listening TCP and UDP sockets (address and port), packet and unix sockets;
  - mount: the mounts the host's mount namespace does not have;
  - IPC: SysV shared memory, semaphore and message queue counts;
  - UTS: the hostname when it differs from the host's;
  - user, PID, cgroup and time namespaces have no readable contents without a process.
  A network namespace held only by a socket is entered through that socket (`pidfd_getfd` and `SIOCGSKNS`, Linux 5.6+).
- **SUSPICIOUS when** an orphan namespace exists, unless it looks like a leftover of a container runtime (then an observation): its only pin is a bind mount in `/run/netns`, `/var/run/netns`, `/run/docker/netns` or `/run/user/<uid>/(docker/|containers/)netns` (or `/run/snapd/ns` for a mount namespace), or a descriptor held by a runtime (`dockerd`, `containerd`, `containerd-shim*`, `runc`, `crun`, `conmon`, `podman`, `crio`, `kubelet`, `systemd`, `snapd`); no process holds a socket in it; and a network namespace has nothing but loopback and no listener. An `ip netns add` namespace with a device or a listener is therefore reported.
- **Canary**: a network namespace created by a thread that then exits, kept alive only by a socket of Zygarde's own. The kernel socket view has to report it as an orphan.
- Limitations: Linux 5.8+ (BTF and the BPF iterators). Namespaces held by something else than a mount, a descriptor or a socket (a BPF netns link, for instance) are not found. At most 256 orphans are entered per scan, within 18 s. Netfilter rules inside an orphan network namespace are not listed; the interface and listener checks usually give it away first.
