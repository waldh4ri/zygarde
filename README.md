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

**Guardian of the Kernel - Advanced Linux Rootkit Detection using eBPF CO-RE**

*"When the ecosystem is threatened, the Cells gather to protect."*

</div>

## Overview

Zygarde is a powerful, portable forensic analysis tool inspired by the Pokémon guardian of the ecosystem. Just as Zygarde's Cells monitor the environment from deep within, this tool uses eBPF (Extended Berkeley Packet Filter) with CO-RE (Compile Once - Run Everywhere) to detect sophisticated rootkit techniques from deep within the Linux kernel.

The tool compiles into a single static binary with no runtime dependencies, making it ideal for incident response and security auditing.

## The Zygarde Architecture

### Core Concept
- **Zygarde Core**: The main orchestrator (`main.go`) that coordinates all Cells
- **Zygarde Cells**: Individual detection modules that monitor specific aspects of the kernel
- **Complete Forme**: When threats are detected, all findings converge for comprehensive analysis

### The Cells

Zygarde implements three specialized Cells for rootkit detection:

#### **Cell 1: Syscall Integrity Cell**
Monitors the system call table for unauthorized modifications.
- Detects `sys_call_table` hooking by rootkits
- Compares kernel memory with expected values from `/proc/kallsyms`
- Uses kprobes to safely read kernel memory
- **Rootkit Technique Detected**: Syscall table modification

#### **Cell 2: Module Visibility Cell**
Reveals kernel modules hidden from user-space.
- Finds kernel modules hidden from `lsmod` and `/sys/module`
- Uses BPF iterators to traverse the kernel's internal module list
- Compares kernel ground truth with user-space visibility
- **Rootkit Technique Detected**: Module list manipulation (list_del)

#### **Cell 3: File Visibility Cell**
Detects executables hidden from directory listings.
- Monitors `execve` syscalls via tracepoints
- Verifies file visibility from user-space
- **Rootkit Technique Detected**: `getdents64` hooking

## Architecture

```
┌─────────────────────────────────────────────────┐
│           Zygarde Core (Binary)                 │
│  (Static, Portable, Single Executable)          │
├─────────────────────────────────────────────────┤
│                                                 │
│  ┌──────────────┐  ┌──────────────┐             │
│  │  Cell        │  │  Cell        │             │
│  │  Interface   │  │  Orchestrator│             │
│  └──────────────┘  └──────────────┘             │
│                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌────────┐ │
│  │  Syscall     │  │  Module      │  │ File   │ │
│  │  Cell        │  │  Cell        │  │ Cell   │ │
│  └──────┬───────┘  └──────┬───────┘  └────┬───┘ │
│         │                 │               │     │
└─────────┼─────────────────┼───────────────┼─────┘
          │                 │               │
          ▼                 ▼               ▼
┌─────────────────────────────────────────────────┐
│           eBPF Programs (CO-RE)                 │
├─────────────────────────────────────────────────┤
│  • kprobe (sys_getuid)                          │
│  • BPF Iterator (module traversal)              │
│  • Tracepoint (sys_enter_execve)                │
└─────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────┐
│            Linux Kernel                         │
└─────────────────────────────────────────────────┘
```

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

### Debug Mode

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

See [DEBUG.md](DEBUG.md) for complete debug mode documentation.

### Example Output

```
 ███████╗╚██╗ ██╔╝ ██████╗  █████╗ ██████╗ ██████╗ ███████╗
 ╚══███╔╝ ╚███╔╝ ██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██╔════╝
   ███╔╝   ╚██╔╝  ██║  ███╗███████║██████╔╝██║  ██║█████╗  
  ███╔╝     ██║   ██║   ██║██╔══██║██╔══██╗██║  ██║██╔══╝  
 ███████╗   ██║   ╚██████╔╝██║  ██║██║  ██║██████╔╝███████╗
 ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝
                                                             
 Guardian of the Kernel - eBPF Rootkit Detection
 Version 0.0.1 - 10% Form

Deploying 3 Zygarde Cells for system analysis...

[Cell 1/3] Executing: Syscall Table Integrity
            Detects sys_call_table hooking by comparing kernel memory with expected addresses
            [+] sys_call_table entry for __x64_sys_getdents64 is intact (0xffffffff81234567) (0.12s)

[Cell 2/3] Executing: Hidden Kernel Modules
            Detects kernel modules hidden from lsmod by comparing kernel module list with /sys/module
            [+] All 145 kernel modules are visible (0.08s)

[Cell 3/3] Executing: Hidden Files in PATH
            Detects executable files that are hidden from directory listings
            [*] Monitoring execve events for 5s...
            [+] No hidden files detected (monitored 23 execve events) (5.11s)

======================================================================
ZYGARDE CORE ANALYSIS - SUMMARY REPORT
======================================================================
Total Cells Deployed: 3
  [+] OK:         3
  [*] SUSPICIOUS: 0
  [-] ERROR:      0

Deactivating Cells...
======================================================================
[+] Ecosystem stable - no threats detected
   Zygarde Cells report: All clear
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
├── main.go                 # Zygarde Core - entry point and Cell orchestrator
├── go.mod                  # Go module definition
├── checks/
│   ├── interface.go        # Cell interface definition
│   ├── syscall.go          # Syscall Integrity Cell
│   ├── modules.go          # Module Visibility Cell
│   └── hidden_files.go     # File Visibility Cell
└── bpf/
    ├── gohunt.bpf.c        # eBPF programs (C)
    └── vmlinux.h           # Kernel type definitions (generated)
```

### Adding New Cells

1. Implement the `Check` interface in a new file under `checks/`
2. Add your eBPF program to `bpf/gohunt.bpf.c` with a unique section name
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

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure `go fmt` and `go vet` pass
5. Submit a pull request

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
- Security researchers studying rootkit techniques
- The Pokémon franchise for inspiring the guardian metaphor

---

<div align="center">

*"Order must be maintained in the ecosystem."* - Zygarde

</div>

