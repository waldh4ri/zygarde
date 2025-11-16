# Zygarde - eBPF-based Rootkit Detection Tool

<div align="center">

```
 ███████╗██╗   ██╗ ██████╗  █████╗ ██████╗ ██████╗ ███████╗
 ╚══███╔╝╚██╗ ██╔╝██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██╔════╝
   ███╔╝  ╚████╔╝ ██║  ███╗███████║██████╔╝██║  ██║█████╗  
  ███╔╝    ╚██╔╝  ██║   ██║██╔══██║██╔══██╗██║  ██║██╔══╝  
 ███████╗   ██║   ╚██████╔╝██║  ██║██║  ██║██████╔╝███████╗
 ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝
```

**Advanced Linux Rootkit Detection using eBPF CO-RE**

</div>

## Overview

Zygarde is a portable forensic analysis tool inspired by the Pokémon guardian of the ecosystem. Just as Zygarde's Cells monitor the environment from deep within, this tool uses eBPF (Extended Berkeley Packet Filter) with CO-RE (Compile Once - Run Everywhere) to detect rootkit techniques from deep within the Linux kernel.

The tool compiles into a single static binary with no runtime dependencies, making it ideal for incident response and security auditing on most recent Linux systems.

> **Note:** *This is an early-stage tool primarily aimed at testing what's feasible with eBPF for DFIR (Digital Forensics and Incident Response). It is under active development and should be considered experimental. For now it supports x86_64 only.*

## Tested Platforms

Zygarde has been tested on the following Linux distributions and kernel versions:

| Distribution | Kernel Version | Architecture |
|-------------|----------------|--------------|
| Ubuntu 22.04 | 5.15.0-91-generic | x86_64 |
| Fedora 39 | 6.6.9-200.fc39.x86_64 | x86_64 |
| Rocky Linux 9 | 5.14.0-362.13.1.el9_3.x86_64 | x86_64 |
| Debian 12 | 6.1.0-17-amd64 | x86_64 |
| RHEL 9 | 5.14.0-362.8.1.el9_3.x86_64 | x86_64 |

## The Zygarde Architecture

### Core Concept
- **Zygarde Core**: The main orchestrator (`main.go`) that coordinates all Cells
- **Zygarde Cells**: Individual detection modules that monitor specific aspects of the kernel

### The Cells

Zygarde implements five specialized Cells (checks) for rootkit detection:

#### **Cell 1: Altered Syscall Table Check** (`altered_syscall_table`)
Monitors the system call table for unauthorized modifications.
- Detects `sys_call_table` hooking by rootkits
- Compares kernel memory with expected values from `/proc/kallsyms`
- Uses kprobes to safely read kernel memory
- **Rootkit Technique Detected**: Syscall table modification

#### **Cell 2: Hidden Kernel Module Check** (`hidden_kernel_module`) (WIP)
Reveals kernel modules hidden from user-space.
- Compares `/proc/modules` with `/sys/module` directory
- Identifies modules visible in kernel but hidden from userspace
- **Rootkit Technique Detected**: Module list manipulation (list_del)

#### **Cell 3: Hidden Process Detection** (`hidden_process`)
Detects processes and threads hidden from user-space.
- Enumerates tasks from kernel using BPF task iterator
- Compares with `/proc` filesystem enumeration
- Identifies processes visible to kernel but hidden from userspace tools
- **Rootkit Technique Detected**: `/proc` manipulation, process hiding

#### **Cell 4: Hidden File Detection** (`hidden_file`)
Detects files hidden from directory listings.
- Monitors file access syscalls (`execve`, `openat`, `open`, `openat2`) via tracepoints
- Verifies file visibility from user-space directory listings
- **Rootkit Technique Detected**: `getdents64` hooking

#### **Cell 5: Hidden eBPF Program Detection** (`hidden_ebpf_program`)
Detects attempts to hide eBPF programs from enumeration using three-way comparison.
- **Ground Truth**: Uses BPF program iterator to enumerate all programs directly from kernel memory 
- **Userspace Enumeration**: Calls `BPF_PROG_GET_NEXT_ID` syscalls which rootkits may intercept
- **Pinned Programs**: Walks `/sys/fs/bpf` to discover pinned programs
- Monitors `sys_bpf` syscalls via tracepoints to detect suspicious ENOENT patterns
- Identifies programs visible to kernel but hidden from userspace enumeration
- **Rootkit Technique Detected**: `sys_bpf` syscall hooking, premature -ENOENT returns forcing early termination of enumeration

## Prerequisites

### Build Requirements
- Go 1.21 or later
- Clang 11 or later
- Linux kernel headers
 - `bpftool` (optional; only if generating `vmlinux.h` locally)
- `libbpf-dev` (for eBPF headers)

### Runtime Requirements
- Linux kernel 5.8+ with BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`)
- Root privileges (for loading eBPF programs)

### Pre-compiled binary
If you're brave enough to run a pre-compiled binary as sudo you can find it
on the [releases page](https://github.com/waldh4ri/zygarde/releases).

### Installing Prerequisites

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y golang clang llvm libbpf-dev linux-headers-$(uname -r)
# Optional: only needed if you want to generate vmlinux.h from this system
sudo apt install -y bpftool
```

**Fedora/RHEL:**
```bash
sudo dnf install -y golang clang llvm libbpf-devel kernel-devel
sudo dnf install -y bpftool
```

**Arch Linux:**
```bash
sudo pacman -S go clang llvm libbpf linux-headers
sudo pacman -S bpf
```

## Building

### Quick Build (Automated)

The easiest way to build Zygarde is using the included `build.sh` script, which handles all steps automatically:

```bash
./build.sh
```

This script will:
- Generate the `vmlinux.h` kernel header (if needed)
- Create eBPF Go bindings
- Compile the static binary

### Step-by-Step Build

#### Step 1: Generate vmlinux.h

The `vmlinux.h` file contains kernel type definitions for CO-RE:

Note:
- You do not need `bpftool` or root to build if you already have a suitable `bpf/vmlinux.h`. You can bring your own `vmlinux.h` (from any kernel with BTF enabled) and skip this step entirely.
- `bpftool` is only required if you want to generate `vmlinux.h` from the current machine. Reading `/sys/kernel/btf/vmlinux` typically requires root.

```bash
# Generate vmlinux.h from your running kernel
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

#### Step 2: Generate eBPF Go Bindings

```bash
# Install bpf2go tool
go install github.com/cilium/ebpf/cmd/bpf2go@latest

# Generate eBPF bindings (from checks directory)
cd checks
go generate
cd ..
```

Or use the Makefile:

```bash
make generate
```

#### Step 3: Build the Binary

```bash
# Static build for maximum portability
CGO_ENABLED=0 go build -ldflags="-s -w" -o zygarde .
```

Or use the Makefile:

```bash
make build
```

The resulting `zygarde` binary is completely standalone and can be copied to any Linux system with a compatible kernel.

## Usage

### Basic Usage

```bash
# Must be run as root
sudo ./zygarde
```

### Command-Line Options

#### JSON Output Mode

For machine-readable output that can be piped to `jq` or other JSON processors:

```bash
# Output results as JSON only (no banner, progress, or colors)
sudo ./zygarde --json

# Pretty-print with jq
sudo ./zygarde --json | jq '.'

# Filter only suspicious findings (status=2)
sudo ./zygarde --json | jq '.[] | select(.status == 2)'

# Get summary of all checks
sudo ./zygarde --json | jq '[.[] | {cell, status, findings: (.suspicious // [] | length)}]'

# Extract specific cell results
sudo ./zygarde --json | jq '.[] | select(.cell == "hidden_process")'
```

**JSON Output Format:**
- `cell`: Cell identifier (e.g., `"hidden_process"`, `"altered_syscall_table"`)
- `status`: Result status (`0` = OK, `1` = Error, `2` = Suspicious)
- `message`: Human-readable summary
- `suspicious`: Array of suspicious findings with descriptions and details
- `duration_seconds`: Execution time in seconds
- `error_message`: Error description (only if status=1)

See `examples/jq_examples.sh` for more advanced jq queries.

#### Debug Mode

For detailed verbose output showing every step of the detection process:

```bash
# Enable debug mode
sudo ./zygarde -d
# or
sudo ./zygarde --debug
```

Debug mode provides detailed information about:
- eBPF program loading and CO-RE relocations
- Kernel symbol resolution
- BPF map configuration
- Kprobe/tracepoint attachment
- Ring buffer operations
- Event processing and parsing
- Cell activation and deactivation

**Note:** Debug mode is automatically disabled when using `--json` to keep JSON output clean.

#### Hidden Files Monitoring Duration

Configure how long the Hidden Files Cell monitors for file access:

```bash
# Monitor for 10 seconds (default is 5 seconds)
sudo ./zygarde --hidden-files-duration=10s

# Monitor for 1 minute
sudo ./zygarde --hidden-files-duration=1m

# Combine with JSON output
sudo ./zygarde --json --hidden-files-duration=30s
```

The duration accepts any valid Go duration format (e.g., `10s`, `1m`, `1m30s`, `500ms`).

### Example Output

```
 ███████╗██╗   ██╗ ██████╗  █████╗ ██████╗ ██████╗ ███████╗
 ╚══███╔╝╚██╗ ██╔╝██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██╔════╝
   ███╔╝  ╚████╔╝ ██║  ███╗███████║██████╔╝██║  ██║█████╗  
  ███╔╝    ╚██╔╝  ██║   ██║██╔══██║██╔══██╗██║  ██║██╔══╝  
 ███████╗   ██║   ╚██████╔╝██║  ██║██║  ██║██████╔╝███████╗
 ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝
                                                                  
 Guardian of the Kernel - eBPF Rootkit Detection
 Version 0.0.1 - 10% Form

Deploying 5 Zygarde Cells for system analysis...

[Cell 1/5] Executing: Altered Syscall Table Check
            Detects sys_call_table hooking by comparing kernel memory with expected addresses
            [+] All 4 checked syscalls are intact (0.12s)

[Cell 2/5] Executing: Hidden Kernel Module Detection
            Detects kernel modules hidden from lsmod by comparing /proc/modules with /sys/module
            [+] All 145 kernel modules are visible (0.08s)

[Cell 3/5] Executing: Hidden Process Detection
            Detects hidden processes/threads by comparing kernel task list (BPF iterator) with userspace /proc enumeration
            [+] No hidden processes detected (428 kernel tasks, 428 /proc entries) (0.15s)

[Cell 4/5] Executing: Hidden File Detection
            Detects files that are hidden from directory listings by monitoring execve, openat, open, and openat2 syscalls on PATH directories
            [+] No hidden files detected (monitored 87 events: map[execve:23 openat:58 open:6]) (20.11s)

[Cell 5/5] Executing: Hidden eBPF Program Detection
            Detects hidden BPF objects by correlating sys_bpf NEXT_ID enumeration with pinned program IDs
            [+] No hidden programs detected (kernel:56, enum:56, pinned:12, ENOENT:1) (0.28s)

======================================================================
ZYGARDE CORE ANALYSIS - SUMMARY REPORT
======================================================================
Total Cells Deployed: 5
  [+] OK:         5
  [*] SUSPICIOUS: 0
  [-] ERROR:      0

Deactivating Cells...
======================================================================
[+] Ecosystem stable - no threats detected
======================================================================
```

### Exit Codes

- `0`: All checks passed, no suspicious activity (Ecosystem stable)
- `1`: One or more Cells failed with errors
- `2`: Suspicious activity detected - potential rootkit (Threat detected!)

## Development

### Project Structure

```
zygarde/
├── main.go                    # Zygarde Core - entry point 
├── go.mod                     # Go module definition
├── build.sh                   # Automated build script
├── checks/
│   ├── interface.go           # Cell interface definition
│   ├── altered_syscall_table.go   # Altered Syscall Table Check
│   ├── hidden_kernel_module.go    # Hidden Kernel Module Check
│   ├── hidden_process.go          # Hidden Process Detection
│   ├── hidden_file.go             # Hidden File Detection
│   └── hidden_ebpf_program.go     # Hidden eBPF Program Detection
├── bpf/
│   ├── zygarde.bpf.c          # eBPF programs (C)
│   └── vmlinux.h              # Kernel type definitions (generated)
└── examples/
    ├── test_json_output.go    # JSON serialization examples
    └── jq_examples.sh         # jq query examples for JSON output
```

### Adding New Cells

1. Implement the `Check` interface in a new file under `checks/`
2. Add your eBPF program to `bpf/zygarde.bpf.c` with a unique section name
3. Register your Cell in `main.go` (in the `allCells` slice)
4. Run `go generate` to update eBPF bindings

Example:

```go
type MyCell struct{}

func NewMyCell() *MyCell {
    return &MyCell{}
}

func (c *MyCell) Name() string {
    return "My Custom Cell"
}

func (c *MyCell) Description() string {
    return "Describes what this Cell monitors"
}

func (c *MyCell) Run() (Result, error) {
    // Implementation
}

func (c *MyCell) Cleanup() error {
    // Cleanup resources
}
```

## Makefile Targets

```bash
make help         # Show all available targets
make generate     # Generate vmlinux.h and eBPF bindings
make build        # Build the zygarde binary
make clean        # Remove built artifacts
make test         # Run tests
make install      # Install to /usr/local/bin
```

## Technical Details

### CO-RE (Compile Once - Run Everywhere)

Zygarde uses eBPF CO-RE, which allows the same eBPF bytecode to run on different kernel versions without recompilation. This is achieved through:

1. **BTF (BPF Type Format)**: Kernel type information available at `/sys/kernel/btf/vmlinux`
2. **CO-RE Relocations**: The `libbpf` loader adjusts field offsets at load time
3. **vmlinux.h**: Generated header with all kernel types

### Security Considerations

- **Root Required**: eBPF programs require `CAP_BPF` and `CAP_PERFMON` capabilities
- **Kernel Lockdown**: May be restricted on systems with kernel lockdown enabled
- **KASLR**: Addresses from `/proc/kallsyms` require root to read
- **False Positives**: Some legitimate kernel modifications may trigger alerts

### Limitations

- Requires kernel 5.8+ with BTF support
- Cannot detect all rootkit techniques (e.g., firmware rootkits)
- Sophisticated rootkits may evade detection by hooking eBPF subsystem
- Hidden file detection requires active process execution
- Hidden process detection may have timing-related false positives due to process lifecycle races

## Troubleshooting

### "failed to load eBPF objects"

**Cause**: Kernel doesn't support required eBPF features

**Solution**: 
```bash
# Check kernel version
uname -r  # Should be 5.8+

# Check BTF support
ls -la /sys/kernel/btf/vmlinux

# Check eBPF features
sudo bpftool feature
```

### "operation not permitted"

**Cause**: Not running as root

**Solution**: Run with `sudo ./zygarde`

### "symbol not found in /proc/kallsyms"

**Cause**: Kernel symbol not available or KASLR hiding addresses

**Solution**: Ensure running as root to see KASLR addresses

## License

This project is licensed under the Dual BSD/GPL License - see the LICENSE file for details.

## References

- [eBPF Documentation](https://ebpf.io/)
- [Cilium eBPF Library](https://github.com/cilium/ebpf)
- [BPF CO-RE](https://nakryiko.com/posts/bpf-portability-and-co-re/)
- [Linux Rootkit Techniques](https://www.kernel.org/doc/html/latest/security/)
- [Zygarde Pokémon](https://bulbapedia.bulbagarden.net/wiki/Zygarde) - Inspiration for the name

## Acknowledgments

- The Cilium team for the excellent Go eBPF library
- The Linux kernel eBPF community

---

<div align="center">

*"Order must be maintained in the ecosystem."* - Zygarde

</div>

