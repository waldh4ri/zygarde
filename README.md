<div align="center">

<pre>
███████╗██╗   ██╗ ██████╗  █████╗ ██████╗ ██████╗ ███████╗
╚══███╔╝╚██╗ ██╔╝██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██╔════╝
  ███╔╝  ╚████╔╝ ██║  ███╗███████║██████╔╝██║  ██║█████╗  
 ███╔╝    ╚██╔╝  ██║   ██║██╔══██║██╔══██╗██║  ██║██╔══╝  
███████╗   ██║   ╚██████╔╝██║  ██║██║  ██║██████╔╝███████╗
╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝
</pre>

**Linux rootkit detection using eBPF CO-RE**

</div>

## Overview

Zygarde is a portable forensic triage tool for Linux. It is organised in detection modules called *Cells*, each comparing two views of the same thing: what the kernel actually holds, read with eBPF, and what userspace is shown through the usual syscalls and files. A rootkit that hides a process, file, module or eBPF program leaves a gap between the two.

It ships as a single static binary with no runtime dependencies, for x86_64 and arm64. Thanks to CO-RE and BTF, the same eBPF bytecode is relocated at load time for the running kernel. It is built on the [cilium/ebpf](https://github.com/cilium/ebpf) Go library.

> **Note:** *Zygarde is experimental, aimed at exploring what eBPF can do for DFIR. A clean result raises the bar for an attacker; it cannot prove that a kernel-level compromise is absent. If you suspect one, capture memory (e.g. AVML/LiME) and analyse it offline (e.g. Volatility 3).*

## The Cells

| Cell | Kernel view | Userspace view | Needs |
|------|-------------|----------------|-------|
| `ebpf_integrity` | canary program and map loaded by Zygarde | `BPF_PROG/MAP_GET_NEXT_ID`, `GET_FD_BY_ID` | root |
| `altered_syscall_table` | `sys_call_table` entries read with a kprobe | handler addresses in `/proc/kallsyms` | x86_64, `CONFIG_KALLSYMS_ALL`, a kernel that still dispatches through the table |
| `hook_inventory` | ftrace's list of patched functions (`enabled_functions`) with each hook's handler | — (attribution: kernel, visible module, BPF, livepatch) | dynamic ftrace, tracefs (mounted temporarily if needed) |
| `inline_hook` | first instructions of syscall handlers and VFS, `/proc` and `/proc/net` functions, read from kernel memory | what the kernel writes there (ftrace NOP or call, `endbr64`), cross-checked with `enabled_functions` | x86_64, Linux 5.2+ |
| `kernel_pointers` | operation tables behind Zygarde's own descriptors on `/proc`, `/proc/net/*`, `/proc/modules`, `/proc/kallsyms`, `/sys/module` and system directories (`file_operations`, `inode_operations`, `seq_operations`, procfs `proc_ops`), read from a BPF task-file iterator | owner of each pointer (kernel, visible module, BPF, trampolines) from `/proc/kallsyms`, `/proc/modules` and `/proc/vmallocinfo`; the table addresses `/proc/kallsyms` gives | BTF, Linux 5.8+ |
| `hidden_kernel_module` | module kobjects in `/sys/module`, module BTF | module list in `/proc/modules`; plus modules configured to load at boot | — |
| `kernel_taint` | kernel taint flags (`/proc/sys/kernel/tainted`) | per-module taint (`/sys/module/*/taint`) | — |
| `hidden_process` | BPF task iterator (with task flags and executable) | `/proc` directory listing; plus processes disguised as kernel threads or run from deleted or memory-backed files | BTF, Linux 5.8+ |
| `hidden_file` | entries the filesystem produces (kprobe on `filldir64`) | entries `getdents64` returns, for sensitive directories, `/proc` and `/sys/module`; plus dot-entries in binary and library directories | BTF, Linux 5.8+ |
| `hidden_ebpf_program` | BPF program iterator, plus Zygarde's own `bpf()` calls traced at syscall exit; holders read from every task's file table | `BPF_PROG_GET_NEXT_ID`, `/sys/fs/bpf` pins; plus where each program is attached (links, perf events, XDP, tc) | BTF, Linux 5.9+ |
| `hidden_socket` | sockets reported over netlink `sock_diag` (what `ss` reads); holders read from every task's file table | `/proc/net/{tcp,udp}{,6}` (what `netstat` reads) | — (owners: BTF, Linux 5.8+) |
| `netfilter_hooks` | netfilter hook functions of every network namespace (IPv4, IPv6, ARP, bridge, per-device ingress/egress), read from `struct net` through a BPF task iterator | owner of each hook function, as for `kernel_pointers` | BTF, Linux 5.8+, netfilter |
| `userspace_hooks` | — (Zygarde doesn't use libc, so these hooks can't fool it) | dynamic linker injection: `/etc/ld.so.preload`, `ld.so.conf` directories, `LD_PRELOAD`/`LD_AUDIT` in process environments | — |

Notes:

- **Syscall table:** since Linux 6.9 (backported to 6.8.5, 6.6.26, 6.1.85 and 5.15.154), x86_64 dispatches syscalls through a `switch` in `x64_sys_call()`, so the table is no longer used and hooking it does nothing. On those kernels the Cell reports SKIPPED, and `hook_inventory` covers how syscalls are hooked there instead.
- **Hooks:** an ftrace callback can only hijack a function if it sets `FTRACE_OPS_FL_IPMODIFY` (flag `I`), and the only legitimate user of that is livepatch. A hook whose handler resolves to no symbol runs in code outside the kernel, visible modules and named BPF programs. Both are SUSPICIOUS. Everything else (BPF trampolines, kprobes, livepatch) is listed as observations. The Cell plants its own fentry (or kprobe) hook as a canary.
- **Taint:** loading a module taints the kernel (out-of-tree `O`, unsigned `E`, …) until reboot. A module taint that no visible module carries means a module hid itself, or was loaded and later unloaded.
- **Inline hooks:** a hook that patches a function's first instructions directly (Reptile-family rootkits such as Mélofée, through khook) bypasses ftrace and kprobes, so `hook_inventory` can't see it. On x86_64 the kernel only ever puts an `endbr64` and a 5-byte ftrace site there: a NOP, or a call to ftrace or one of its trampolines. A jump out of the kernel's text, or a call that `enabled_functions` doesn't account for, is SUSPICIOUS. The reader's own kprobe on `getuid` serves as a canary: its patch must show up when that function is read.
- **Function pointers:** rootkits hide entries by swapping one pointer in an operations table, leaving the code intact: `iterate_shared` of `/proc` (adore-ng), the `show` of `/proc/net/tcp`'s `seq_operations` (Snapekit, VoidLink), the `seq_operations` of `/proc/modules`. Zygarde opens those files itself, without reading them, and a BPF task-file iterator reads, from each `struct file`, the `file_operations` and `inode_operations` entries, the `seq_file`'s operations (recognised by `seq_file->file` pointing back at the file) and, for procfs entries, the `proc_dir_entry`'s `proc_ops` and `seq_ops` (which covers the per-protocol tables `/proc/net/{tcp,udp}{,6}` open with). Every pointer must belong to the kernel or to the module implementing the file (the filesystem's module, read from `super_block->s_type->owner`, or the protocol's: `ipv6`, `unix`, `af_packet`). Code that no visible module owns, or an unrelated module, is SUSPICIOUS; so is a table outside kernel and module memory (a copied table; `single_open()`'s own heap table is expected). The show function of Zygarde's own `/proc/net/tcp` must read back as `tcp4_seq_show` (canary).
- **Attribution:** an address belongs to the kernel if it lies in its image (`_stext`–`_end` in `/proc/kallsyms`); otherwise to the `/proc/vmallocinfo` allocation containing it, owned by the modules, BPF programs or trampolines whose symbols (`[module]`, `[bpf]`, `[__builtin__ftrace]`, `[__builtin__kprobes]`) or `/sys/module/*/sections` fall inside it. Code in an allocation nothing visible owns runs from a hidden module. Without `/proc/vmallocinfo`, ownership falls back to distances from module symbols, and tables it can't place are only observations. Allocations shared between modules (execmem caches, Linux 6.14+) are attributed to the nearest module below the address.
- **Symbol table filtering:** `/proc/kallsyms` is cross-checked against kernel memory: the tables of `/proc`, `/proc/net/tcp`, `/proc/modules` and `/proc/kallsyms` itself must be where it says (when built with `CONFIG_KALLSYMS_ALL`), and every kernel function pointer read must start a function it names. A disagreement means a table was replaced or `/proc/kallsyms` is being filtered (Singularity sanitises it): SUSPICIOUS.
- **Netfilter hooks:** kernel backdoors listen for "magic packets" from a netfilter hook, which sees every packet before any socket (Reptile, Diamorphine variants, Syslogk, FontOnLake, VoidLink). For every network namespace a task lives in, Zygarde reads the `nf_hook_entries` of each hook point and of the first 32 network devices, and attributes each hook function. The kernel, visible modules (conntrack, iptables, nftables, bridge) and BPF netfilter links are observations; a function no visible module owns is SUSPICIOUS. On Linux 6.4+ a do-nothing BPF netfilter link on Zygarde's IPv4 `LOCAL_OUT` is the canary. Namespaces no task lives in (only pinned in `/run/netns`) are not covered.
- **Kernel modules:** rootkits unlink themselves from the module list (`list_del`, which hides them from `lsmod`) or delete their kobject (`kobject_del`). Only loadable modules have `/sys/module/<name>/initstate`, which separates them from built-ins.
- **Boot-time modules:** the same Cell lists modules configured to load at boot (`modules-load.d`, `/etc/modules`, `modprobe.d`, and `insmod`/`modprobe` lines in `rc.local`, `rc.modules` and shell profiles). It flags an `insmod` of a file outside `/lib/modules/$(uname -r)` (Mélofée loads `/etc/intel_audio/intel_audio.ko` from `rc.modules`), an `install` directive that runs something other than the usual `true`/`false`/`modprobe`/`sysctl`, and a configuration file hidden from its directory listing. Module names are observations: `modprobe` only searches the running kernel's module tree, so a name missing from it can't load.
- **Processes:** `/proc` lists only processes, not threads, so the comparison is per process. The kernel view is taken before and after reading `/proc`, which rules out processes that start or exit mid-scan. PIDs are translated into Zygarde's PID namespace, so it also works inside containers.
- **Disguised processes:** a process named like a kernel thread (`kworker/…`, or a `[bracketed]` command line) that the kernel doesn't flag as one (`PF_KTHREAD`) is SUSPICIOUS: renaming can't fake the kernel's own flags. A process running from a `memfd`, `/dev/shm`, `/tmp` or a hidden directory, or from a deleted file, is an observation, and SUSPICIOUS when it runs as root (deleted binaries in package-managed directories, left behind by upgrades, stay observations). Command lines padded with long runs of blanks to push arguments out of view are observations.
- **Files:** Zygarde lists sensitive directories (binaries, libraries, persistence locations, `/tmp`, `/dev/shm`, home directories), `/proc` and `/sys/module` itself. A kprobe on `filldir64`, the callback that copies each entry into the `getdents64` buffer, records what the filesystem produced. An entry produced but not returned was filtered afterwards, by a hooked `getdents64` or by a program rewriting the result buffer. Hiding inside the filesystem code itself is not covered (`inline_hook` checks that `filldir64` and its callers are unpatched).
- **Dot-entries in system directories:** `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/lib*` and `/usr/lib*` hold no dot-entries on a stock install (except `.build-id`, FIPS `.hmac` files and Gentoo's `.keep*`). Others are observations, and SUSPICIOUS when they hold executables (Scales keeps a trojaned `sudo` in `/usr/bin/.local`).
- **BPF attachments and owners:** eBPF rootkits (LinkPro, Scales) hide entries from programs attached to syscall tracepoints, which don't go through ftrace. The inventory lists where every program is attached, from BPF links (`BPF_LINK_GET_NEXT_ID`), BPF-running perf events (`BPF_TASK_FD_QUERY`, as `bpftool perf` does, which also covers attachments without a link) and network interfaces (XDP and tc filters over netlink). A BPF task-file iterator reads which processes hold each program and link straight from the kernel's file tables. A program held only by processes hidden from `/proc` is SUSPICIOUS; so is a program on a sensitive attach point (directory listing, `bpf()`, `kill`, `ptrace`, raw `sys_enter`/`sys_exit`) that can rewrite user memory or return values, and an XDP or tc program that is hidden or unnamed (covert channels, e.g. LinkPro's port knocking). Other attachments, unowned programs and `/sys/fs/bpf` pins (with the programs using each pinned map) are observations. Zygarde's own programs must be attributed to it (canary).
- **Sockets:** `netstat` reads `/proc/net` and `ss` uses netlink `sock_diag`; rootkits usually filter only one (LinkPro hides its listener from `/proc/net`). A socket present in one view but not the other, in two snapshots, is SUSPICIOUS, as is a socket held only by processes hidden from `/proc` (how Sandfly found Scales). Zygarde's own TCP and UDP canary sockets must appear in both views and be attributed to it. Kernels built without `CONFIG_INET_DIAG` only get the ownership check. Only Zygarde's network namespace is covered.
- **Userspace hooks:** `/etc/ld.so.preload` with entries is SUSPICIOUS (LinkPro falls back to it when its eBPF part can't load), as are `ld.so.conf` directories under `/tmp`, `/dev/shm`, hidden or world-writable directories, and preloaded libraries that are missing, live in such places or are hidden from their directory listing. Processes started with `LD_PRELOAD`/`LD_AUDIT` or an unusual `LD_LIBRARY_PATH` are observations (profilers, allocators and EDRs use them).

## Resisting tampering

A rootkit can attack the scanner itself. Zygarde is built to make that visible:

- **Canaries.** Cells plant objects they know exist (a child process, a file, their own BPF programs, their own syscalls) and look for them in every view. A canary missing from a view means that view is filtered: SUSPICIOUS.
- **Blocked eBPF is a finding.** A `bpf()` permission error is reported as SUSPICIOUS when every other source says it should work: root, no seccomp filter, and a lockdown mode that allows it. A kernel that simply lacks a feature gives SKIPPED instead.
- **Supervised worker.** Cells run in a child process. If it is killed mid-Cell, the parent reports the signal (SUSPICIOUS), cleans up, and resumes the remaining Cells in a new worker. A Cell that hangs past its timeout is reported too.
- **No libc.** The binary is static Go and makes syscalls directly, so `LD_PRELOAD` and libc-hooking rootkits don't affect it. `userspace_hooks` reports those hooks instead, since they still fool every other tool.

## Usage

```bash
sudo ./zygarde                          # run all checks, human-readable report
sudo ./zygarde -o report.json           # same, and save the full JSON report
sudo ./zygarde --json | jq '.results[] | select(.status == 2)'
sudo ./zygarde --cells hidden_process,hidden_kernel_module
sudo ./zygarde -v                       # also show what each check does, observations and canaries
./zygarde --list                        # list checks
```

| Flag | Meaning |
|------|---------|
| `-o`, `--output <file>` | also save the JSON report to a file (mode 0600) |
| `--json` | print the JSON report on stdout instead of text |
| `-v` | verbose: check descriptions, observations (e.g. legitimate hooks) and canaries |
| `--no-color` | no colors; they are also off when `NO_COLOR` is set or output isn't a terminal |
| `--cells a,b` | run only these checks (see `--list`) |
| `--btf <file>` | external BTF for kernels without `/sys/kernel/btf/vmlinux` |
| `--no-isolation` | run checks in-process instead of in a supervised worker |
| `-d`, `--debug` | debug logging on stderr |

### Reading the report

The text report starts with the host (name, distribution, kernel, architecture, BTF, lockdown, time), then prints one line per check, followed by:

- **Findings**: for each one, what was observed, the evidence, **why** it points to tampering, and what innocent explanation to **rule out** first.
- **Coverage**: which checks didn't run on this system and why, and which ran only partly (marked `*`). A clean verdict only covers what actually ran.
- **Verdict** and **next steps**: for a suspicious result, preserve evidence before touching the system.

| Status | JSON `status` | Meaning |
|--------|---------------|---------|
| OK | 0 | the check ran and found nothing |
| ERROR | 1 | the check could not complete |
| SUSPICIOUS | 2 | evidence of hiding or tampering |
| SKIPPED | 3 | the check does not apply to this system (reason in `message`) |

The exit code is `2` if anything is SUSPICIOUS, `1` if any check errored, and `0` otherwise.

### JSON report

`--json` and `--output` produce one object: `tool`, `version`, `host` (`hostname`, `distro`, `kernel`, `arch`, `lockdown`, `btf`, `boot_id`), `started_at`, `finished_at`, `verdict` (`clean`, `suspicious` or `incomplete`), `findings` (count) and `results`. Each result has `cell`, `name`, `status`, `status_text`, `message`, `findings` (`description`, `details`, `why`, `benign_causes`), `observations`, `canaries` (`canary`, `view`, `observed`), `limitations`, `error` and `duration_seconds`.

## Building

The generated eBPF objects and Go bindings (`cells/*/*_bpfel.{go,o}`, `internal/fdowner/*_bpfel.{go,o}`) are committed, so a plain Go build needs no clang:

```bash
make build      # ./zygarde for this machine (CGO_ENABLED=0, static)
make dist       # dist/zygarde-linux-{amd64,arm64}
```

After changing a `.bpf.c` file, regenerate the bindings with clang:

```bash
make generate         # needs clang and llvm
make docker-generate  # or inside the pinned toolchain image (build/Dockerfile)
```

CI regenerates the bindings in that image and fails if they differ from what is committed.

### Developing without a Linux machine

Every target has a `docker-` variant that runs in the toolchain image, from Linux, macOS or Windows:

```bash
make docker-test     # go vet + unit tests
make docker-build
make docker-run ARGS="--cells hidden_file"   # privileged container on the Docker host's kernel
```

## Compatibility

- **Runtime:** Linux 5.8+ with BTF (`CONFIG_DEBUG_INFO_BTF=y`) for most Cells, root privileges, x86_64 or arm64. Cells probe for the kernel features they need (BTF types rather than version numbers, so distribution backports are honoured) and report SKIPPED when something is missing.
- **Kernel lockdown:** in `confidentiality` mode, BPF may not read kernel memory, so `altered_syscall_table`, `inline_hook`, `kernel_pointers`, `netfilter_hooks`, `hidden_process` and `hidden_file` skip, and `hook_inventory` skips because tracefs is locked. `hidden_ebpf_program` skips too: it only reads user memory, which lockdown allows, but cilium/ebpf detects helper support by probing `bpf_probe_read_kernel()`, gets denied, and downgrades `bpf_probe_read_user()` to the legacy `bpf_probe_read()`, which lockdown forbids. `hidden_socket` runs without its ownership check. `ebpf_integrity`, `hidden_kernel_module`, `kernel_taint` and `userspace_hooks` still run. `integrity` mode (the usual Secure Boot default) affects nothing.
- **No tracefs needed:** syscall tracing uses BTF-typed raw tracepoints (`tp_btf`), which work where tracefs isn't mounted, such as in containers.
- **Verified:** in VMs with no false positives: upstream 4.19, 5.4, 5.10, 5.15, 6.1, 6.6, 6.12, 6.18 and 7.2; Ubuntu 20.04 to 26.04, Debian 11 to 13, Rocky 8 to 10, Fedora 44, Amazon Linux 2023, openSUSE Leap 15.6 and 16.0; arm64 Debian 12 and 13, Ubuntu 22.04 and 24.04, Rocky 9 and Fedora 44 (emulated); kernel lockdown in integrity and confidentiality modes. Fixture targets confirm each detection fires (see [Testing across kernels](#testing-across-kernels)).

## Testing across kernels

Unit tests (`make test`) cover parsing and decision logic. Compatibility is tested by booting real kernels with QEMU/KVM inside a privileged container (`build/vmtest.Dockerfile`), then running Zygarde in each:

```bash
make vm-upstream                        # upstream LTS kernels (ghcr.io/cilium/ci-kernels via vimto), ~1 min
make vm-distro                          # official cloud images from test/vm/distros.txt, first run downloads them
make vm-distro DISTROS="rocky-8 debian-12" JOBS=4
make vm-report                          # Markdown matrix of test/vm/out
```

On a clean VM every Cell must be OK or SKIPPED, with every canary observed. The report exits non-zero otherwise. Distro targets can raise kernel lockdown before running, to test lockdown handling. CI runs the upstream matrix on every push.

Fixture targets (`*-fixtures` in `test/vm/distros.txt`) check that detections fire: `test/vm/fixtures.sh` plants benign stand-ins (a system-wide preload, a `sudo` in `/usr/bin/.local`, a Mélofée-style `insmod` in `rc.modules`, a `modprobe.d` install command, a root process running from a deleted file in `/tmp`), and `test/vm/fixture` attaches do-nothing programs to `sys_enter_getdents64`, a kprobe, XDP and tc egress on `lo` while running a child disguised as `[kworker/0:7]`. The report checks each target against `test/vm/fixtures.expect` instead of requiring a clean result.

## Development

### Layout

```
cmd/zygarde/            CLI, output, supervisor wiring
internal/core/          Cell interface, Result/Status, Env probing, error classification
internal/supervisor/    parent/worker process split and protocol
internal/canary/        canary processes and files
internal/bpfutil/       loading, iterators, enumeration helpers
internal/fdowner/       BPF task-file iterator: which processes hold BPF objects and sockets
internal/kattr/         kernel address attribution: kernel, visible module, BPF, trampolines or unknown
internal/kernel/        kallsyms, lockdown, tracefs, /proc/self/status parsing
internal/netlink/       minimal netlink dumps (sock_diag, links, qdiscs, tc filters)
cells/<name>/           one package per Cell: <name>.bpf.c + generated bindings + Go logic
test/vm/                kernel matrix harness: upstream.sh, distro.sh, inside.sh, report/,
                        fixtures.sh + fixture/ + fixtures.expect (detections must fire)
bpf/include/            vendored libbpf headers, per-arch vmlinux.h, zygarde.h
build/Dockerfile        pinned toolchain (Go, clang)
build/vmtest.Dockerfile VM test harness (QEMU, vimto, cloud-image tools)
```

### Adding a Cell

1. Create `cells/<name>/` with a `.bpf.c` file (start it with `//go:build ignore`) and a `//go:generate go tool bpf2go ...` line, copying an existing Cell.
2. Implement `core.Cell`:
   - `Supported(env)` returns `core.Skip(...)` when the kernel lacks what the Cell needs; prefer `env.RequireBTFType`.
   - `Run(ctx, env, rec)` records results: `rec.Suspicious(core.Finding{...})` with evidence in `Details`, plus `Why` (why it points to tampering) and `Benign` (what to rule out); `rec.Canary` for planted objects; `rec.Limit` for any part that could not run here; `rec.Observe` for context; `rec.Message` for the one-line summary. Wrap failing bpf() operations with `core.WrapBPF` so denials are classified correctly. Release every kernel resource before returning.
3. Load only your own objects with `bpfutil.Load`, and filter on Zygarde's own process with `is_target()` and `bpfutil.SetTarget`.
4. Register the Cell in `cmd/zygarde/main.go` and run `make generate`.

## References

- [cilium/ebpf](https://github.com/cilium/ebpf)
- [BPF CO-RE (Andrii Nakryiko)](https://nakryiko.com/posts/bpf-portability-and-co-re/)
- [BPF iterators](https://docs.kernel.org/bpf/bpf_iterators.html)
- [x86/syscall: Don't force use of indirect calls for system calls](https://git.kernel.org/torvalds/c/1e3ad78334a6)
- [libbpf/vmlinux.h](https://github.com/libbpf/vmlinux.h) (source of `bpf/include/arm64/vmlinux.h`)
- Rootkits and detection guidance behind the inventory, ownership, socket, preload and inline-hook checks: Synacktiv, [LinkPro : analyse d'un rootkit eBPF](https://www.synacktiv.com/publications/linkpro-analyse-dun-rootkit-ebpf); Sandfly Security, [Linux Scales eBPF Rootkit Detection and Analysis](https://sandflysecurity.com/blog/linux-scales-ebpf-rootkit-detection-and-analysis); ExaTrack, [Mélofée](https://exatrack.com/publications/melofee.html); Elastic Security Labs, [Linux Rootkits 2: Caught in the Act](https://www.elastic.co/security-labs/threat-command/linux-rootkits-2-caught-in-the-act); LinuxSecurity, [Linux Rootkit Detection & Defense Guide](https://linuxsecurity.com/features/linux-rootkit-detection-defense-guide)

## License

Dual BSD/GPL; see LICENSE. The vendored libbpf headers are LGPL-2.1 OR BSD-2-Clause.
