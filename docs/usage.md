# Usage and reports

## Command line

```
zygarde [flags]
```

| Flag | Meaning |
|------|---------|
| `-o`, `--output <file>` | Save the JSON report to a file. Checked writable before the scan starts; written atomically with mode 0600 |
| `--preserve-dir <dir>` | Save copies of volatile suspicious binaries (deleted or memfd-backed) into `<dir>` (directory mode 0700, files 0600) |
| `--json` | Print the full JSON report on stdout instead of the text report |
| `-v` | Verbose: show what each check does, its observations (for example legitimate hooks) and canaries |
| `--no-color` | Disable colors. They are also off when `NO_COLOR` is set, `TERM=dumb`, or output is not a terminal |
| `--cells a,b` | Run only these Cells, in the given order (IDs from `--list`) |
| `--list` | List Cell IDs and descriptions, then exit |
| `--btf <file>` | External BTF file, for kernels without `/sys/kernel/btf/vmlinux` |
| `--no-isolation` | Run Cells inside the main process instead of a supervised worker. No hard timeout: a stuck Cell is only stopped by Ctrl-C (a second Ctrl-C exits at once). Mainly for debugging |
| `--allow-panic-on-oops` | Run even though `kernel.panic_on_oops=1`. By default Zygarde refuses: it reads kernel-backed files that a rootkit may have left dangling, and a kernel oops while reading one would panic and reboot the machine, losing the volatile evidence. Prefer `sysctl -w kernel.panic_on_oops=0` for the scan and restoring it afterwards |
| `-d`, `--debug` | Debug logging on stderr |
| `--version` | Print the version |

Ctrl-C, `SIGTERM` and `SIGHUP` (a dropped SSH session) stop the scan cleanly: the worker gets 3 seconds to detach probes and remove canaries before it is killed.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | every Cell was OK or SKIPPED |
| `1` | at least one Cell failed (ERROR), nothing SUSPICIOUS; also when the JSON report could not be saved |
| `2` | at least one Cell is SUSPICIOUS |

## Statuses

| Status | JSON `status` | Meaning |
|--------|---------------|---------|
| OK | `0` | The Cell ran and found nothing |
| ERROR | `1` | The Cell could not complete (see `error`) |
| SUSPICIOUS | `2` | Evidence of hiding or tampering |
| SKIPPED | `3` | The Cell does not apply to this system (reason in `message`) |

A Cell becomes SUSPICIOUS if it recorded any finding, if one of its canaries was not observed, or if `bpf()` was denied when it should have worked. When several outcomes apply, the most severe wins: SUSPICIOUS, then ERROR, then OK, then SKIPPED.

SKIPPED is not a failure: Cells check for the BTF types and features they need (not kernel version numbers, so distribution backports are honoured) and decline to run when something is missing.

## The text report

1. **Header**: host name, distribution, kernel, architecture, BTF, lockdown mode, time.
2. **One line per Cell** as it completes, with status and duration. A `*` marks a Cell that ran only partly.
3. **Findings**: for each, *what* was observed, the *evidence*, *why* it points to tampering, and which innocent explanation to *rule out* first.
4. **Coverage**: Cells that did not run, and the parts of other Cells that could not (limitations). A clean verdict covers only what ran.
5. **Verdict** (`clean`, `suspicious`, `incomplete`) and **next steps**. For a suspicious result the advice is to preserve evidence before touching the host.

### How to triage a SUSPICIOUS finding

1. Read the *benign causes* line first. Common ones: a security product (EDR, auditd plugin, BPF-LSM) loaded a hook or program; a package manager mid-update replaced a library; a legitimate livepatch.
2. Re-run the single Cell with `-v` (`--cells <id> -v`) to see the observations around the finding.
3. Check whether another Cell agrees. Rootkits usually trip several: for example a hidden module shows up in `hidden_kernel_module`, `kernel_taint` and `hook_inventory`.
4. If it is not explained, save a report (`-o`), keep `--preserve-dir` copies, and capture memory before rebooting or removing anything.

## JSON report

`--json` and `--output` produce one object:

| Field | Content |
|-------|---------|
| `tool`, `version` | `"zygarde"` and its version |
| `host` | `hostname`, `machine_id`, `distro`, `kernel`, `kernel_version`, `arch`, `lockdown`, `kptr_restrict`, `btf`, `boot_id`, `boot_time` |
| `scanner_footprint` | `pid`, `worker_pids`, `binary_sha256`, `args`, `artifacts`: everything Zygarde created, to filter scanner noise out of audit/EDR timelines |
| `started_at`, `finished_at` | UTC timestamps |
| `verdict` | `clean`, `suspicious` or `incomplete` (no findings but a Cell errored) |
| `findings` | total number of findings |
| `results` | one object per Cell, below |

Each entry of `results`:

| Field | Content |
|-------|---------|
| `cell`, `name` | Cell ID and display name |
| `status`, `status_text` | numeric status and its name |
| `message` | one-line summary, or the skip reason |
| `findings[]` | `description`, `details` (evidence map), `why`, `benign_causes` |
| `observations[]` | same shape as findings; context only. Capped at 2000 per Cell, the overflow is counted under `limitations` |
| `canaries[]` | `canary`, `view`, `observed` |
| `limitations[]` | parts that could not run here |
| `footprint[]` | `kind`, `value` of transient objects created by the Cell |
| `error` | error text when the Cell failed |
| `duration_seconds` | wall time |

Examples:

```bash
# Cells that are suspicious, with their findings
sudo ./zygarde --json | jq '.results[] | select(.status == 2) | {cell, findings}'

# Everything that was not checked, and why
sudo ./zygarde --json | jq '.results[] | select(.status == 3 or (.limitations // [] | length > 0)) | {cell, message, limitations}'

# Fleet use: act on the exit code, keep the report
sudo ./zygarde -o /var/tmp/zyg-$(hostname).json; echo $?
```

## Reading a result as a whole

- **Clean verdict + SKIPPED Cells**: nothing was found by the checks that could run. Look at Coverage to see what that excludes (for example `altered_syscall_table` is SKIPPED on any kernel that no longer dispatches through the table, and everything that reads kernel memory is skipped under lockdown `confidentiality`).
- **Incomplete**: no findings, but at least one Cell failed. Treat it as unknown, not clean. A worker killed mid-Cell is reported as SUSPICIOUS rather than ERROR unless the kernel's OOM counters moved.
- **A missed canary**: the view in question is being filtered. The Cell's other clean answers for that view cannot be trusted.
