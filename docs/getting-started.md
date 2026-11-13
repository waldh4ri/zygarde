# Getting started

## Requirements

| | |
|---|---|
| OS | Linux, x86_64 or arm64 |
| Privileges | root, or `CAP_BPF`/`CAP_SYS_ADMIN` **in the initial user namespace** |
| Kernel | 5.8+ with BTF (`CONFIG_DEBUG_INFO_BTF=y`) for most Cells. Older kernels run the Cells that do not need BTF and report the others as SKIPPED |
| Runtime deps | none (static Go binary, no libc) |

Zygarde refuses to start without the privileges and prints `zygarde needs CAP_BPF/CAP_SYS_ADMIN in the initial user namespace (try: sudo zygarde)`. Capabilities are read from `/proc/self/status`, so a container running as UID 0 with those capabilities dropped is correctly treated as unprivileged.

## Get a binary

Build it (a Go toolchain is enough, no clang needed, because the compiled eBPF objects are committed):

```bash
make build      # ./zygarde for this machine
make dist       # dist/zygarde-linux-amd64 and dist/zygarde-linux-arm64
```

No Go or Linux on your workstation? Use the toolchain container (Docker required, works from Windows and macOS):

```bash
make docker-dist
```

Copy the binary to the target host. It needs no installation. Run it from a path that is not a noexec mount (on hardened hosts `/tmp` often is; `/usr/local/sbin` works).

## First run

```bash
sudo ./zygarde
```

A scan takes a few seconds to about a minute. It prints one line per Cell as it runs, then the findings, coverage, verdict and next steps. See [Usage and reports](usage.md) for how to read them.

Common variations:

```bash
sudo ./zygarde -v                                       # explain each check, show observations and canaries
sudo ./zygarde --cells hidden_process,hidden_socket     # only some Cells
sudo ./zygarde -o report.json --preserve-dir ./evidence # keep a JSON report and copies of deleted/memfd binaries
sudo ./zygarde --json | jq '.results[] | select(.status == 2)'
./zygarde --list                                        # Cell IDs and descriptions (no root needed)
```

The exit code is `0` (nothing found), `1` (a Cell could not complete) or `2` (something is SUSPICIOUS), which makes it usable from fleet tooling.

## Try it without a Linux machine

```bash
make docker-run                                 # privileged container on the Docker host's kernel
make docker-run ARGS="--cells hidden_file -v"
```

This runs on the kernel of the Docker host (on Docker Desktop, its VM), inside a Debian container. Expect SKIPPED for Cells that need tracefs or that the VM kernel lacks. It is a smoke test, not a representative scan.

## Running in containers and restricted environments

- Use `--privileged --pid=host` so Zygarde sees the host's processes. Without `--pid=host` it scans the container's PID namespace only (PIDs are translated, so it still works there).
- tracefs does not need to be mounted: syscall tracing uses BTF raw tracepoints, and `hook_inventory` mounts tracefs in a private mount namespace when it needs it.
- If `bpf()` is blocked by seccomp or an LSM profile, the affected Cells report ERROR or SKIPPED and say why. When the environment says `bpf()` should work (privileged, no seccomp, unconfined, lockdown allows it) but the kernel refuses with a permission error, that is itself reported as SUSPICIOUS.

## Before scanning a host you already suspect

Zygarde loads eBPF programs, so it leaves traces in the live kernel (BPF object IDs, PID allocations, audit events). It lists them in the report under `scanner_footprint` so they can be told apart from attacker activity. If the host is high-value and you suspect compromise, capture memory first (AVML or LiME) and analyse it offline, for example with Volatility 3. Zygarde is best for fast triage across many hosts.

## Next

- [Usage and reports](usage.md): flags, report format, interpreting results
- [Compatibility](compatibility.md): what runs on which kernel
