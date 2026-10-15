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
| `hidden_kernel_module` | module kobjects in `/sys/module` | module list in `/proc/modules` | — |
| `kernel_taint` | kernel taint flags (`/proc/sys/kernel/tainted`) | per-module taint (`/sys/module/*/taint`) | — |
| `hidden_process` | BPF task iterator | `/proc` directory listing | BTF, Linux 5.8+ |
| `hidden_file` | entries the filesystem produces (kprobe on `filldir64`) | entries `getdents64` returns, for sensitive directories, `/proc` and `/sys/module` | BTF, Linux 5.8+ |
| `hidden_ebpf_program` | BPF program iterator, plus Zygarde's own `bpf()` calls traced at syscall exit | `BPF_PROG_GET_NEXT_ID`, `/sys/fs/bpf` pins | BTF, Linux 5.9+ |

Notes:

- **Syscall table:** since Linux 6.9 (backported to 6.8.5, 6.6.26, 6.1.85 and 5.15.154), x86_64 dispatches syscalls through a `switch` in `x64_sys_call()`, so the table is no longer used and hooking it does nothing. On those kernels the Cell reports SKIPPED, and `hook_inventory` covers how syscalls are hooked there instead.
- **Hooks:** an ftrace callback can only hijack a function if it sets `FTRACE_OPS_FL_IPMODIFY` (flag `I`), and the only legitimate user of that is livepatch. A hook whose handler resolves to no symbol runs in code outside the kernel, visible modules and named BPF programs. Both are SUSPICIOUS. Everything else (BPF trampolines, kprobes, livepatch) is listed as observations. The Cell plants its own fentry (or kprobe) hook as a canary.
- **Taint:** loading a module taints the kernel (out-of-tree `O`, unsigned `E`, …) until reboot. A module taint that no visible module carries means a module hid itself, or was loaded and later unloaded.
- **Kernel modules:** rootkits unlink themselves from the module list (`list_del`, which hides them from `lsmod`) or delete their kobject (`kobject_del`). Only loadable modules have `/sys/module/<name>/initstate`, which separates them from built-ins.
- **Processes:** `/proc` lists only processes, not threads, so the comparison is per process. The kernel view is taken before and after reading `/proc`, which rules out processes that start or exit mid-scan. PIDs are translated into Zygarde's PID namespace, so it also works inside containers.
- **Files:** Zygarde lists sensitive directories (binaries, libraries, persistence locations, `/tmp`, `/dev/shm`, home directories), `/proc` and `/sys/module` itself. A kprobe on `filldir64`, the callback that copies each entry into the `getdents64` buffer, records what the filesystem produced. An entry produced but not returned was filtered afterwards, by a hooked `getdents64` or by a program rewriting the result buffer. Hiding inside the filesystem code itself is not covered.

## Resisting tampering

A rootkit can attack the scanner itself. Zygarde is built to make that visible:

- **Canaries.** Cells plant objects they know exist (a child process, a file, their own BPF programs, their own syscalls) and look for them in every view. A canary missing from a view means that view is filtered: SUSPICIOUS.
- **Blocked eBPF is a finding.** A `bpf()` permission error is reported as SUSPICIOUS when every other source says it should work: root, no seccomp filter, and a lockdown mode that allows it. A kernel that simply lacks a feature gives SKIPPED instead.
- **Supervised worker.** Cells run in a child process. If it is killed mid-Cell, the parent reports the signal (SUSPICIOUS), cleans up, and resumes the remaining Cells in a new worker. A Cell that hangs past its timeout is reported too.
- **No libc.** The binary is static Go and makes syscalls directly, so `LD_PRELOAD` and libc-hooking rootkits don't affect it.

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

The generated eBPF objects and Go bindings (`cells/*/*_bpfel.{go,o}`) are committed, so a plain Go build needs no clang:

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
- **Kernel lockdown:** in `confidentiality` mode, BPF may not read kernel memory, so `altered_syscall_table`, `hidden_process` and `hidden_file` skip, and `hook_inventory` skips because tracefs is locked. `hidden_ebpf_program` skips too: it only reads user memory, which lockdown allows, but cilium/ebpf detects helper support by probing `bpf_probe_read_kernel()`, gets denied, and downgrades `bpf_probe_read_user()` to the legacy `bpf_probe_read()`, which lockdown forbids. `ebpf_integrity`, `hidden_kernel_module` and `kernel_taint` still run. `integrity` mode (the usual Secure Boot default) affects nothing.
- **No tracefs needed:** syscall tracing uses BTF-typed raw tracepoints (`tp_btf`), which work where tracefs isn't mounted, such as in containers.
- **Verified so far:** x86_64, Linux 6.6.87 (WSL2), inside a privileged container. arm64 binaries build but are untested. Testing across a kernel matrix is the next milestone.

## Testing across kernels

Unit tests (`make test`) cover parsing and decision logic. Compatibility is tested by booting real kernels with QEMU/KVM inside a privileged container (`build/vmtest.Dockerfile`), then running Zygarde in each:

```bash
make vm-upstream                        # upstream LTS kernels (ghcr.io/cilium/ci-kernels via vimto), ~1 min
make vm-distro                          # official cloud images from test/vm/distros.txt, first run downloads them
make vm-distro DISTROS="rocky-8 debian-12" JOBS=4
make vm-report                          # Markdown matrix of test/vm/out
```

On a clean VM every Cell must be OK or SKIPPED, with every canary observed. The report exits non-zero otherwise. Distro targets can raise kernel lockdown before running, to test lockdown handling. CI runs the upstream matrix on every push.

## Development

### Layout

```
cmd/zygarde/            CLI, output, supervisor wiring
internal/core/          Cell interface, Result/Status, Env probing, error classification
internal/supervisor/    parent/worker process split and protocol
internal/canary/        canary processes and files
internal/bpfutil/       loading, iterators, enumeration helpers
internal/kernel/        kallsyms, lockdown, /proc/self/status parsing
cells/<name>/           one package per Cell: <name>.bpf.c + generated bindings + Go logic
test/vm/                kernel matrix harness: upstream.sh, distro.sh, inside.sh, report/
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

## License

Dual BSD/GPL; see LICENSE. The vendored libbpf headers are LGPL-2.1 OR BSD-2-Clause.
