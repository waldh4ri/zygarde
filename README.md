# GoHunt - eBPF-based Rootkit Detection Tool

<div align="center">

```
  ██████╗  ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗
 ██╔════╝ ██╔═══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝
 ██║  ███╗██║   ██║███████║██║   ██║██╔██╗ ██║   ██║   
 ██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   
 ╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   
  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   
```

**Advanced Linux Rootkit Detection using eBPF CO-RE**

</div>

## Overview

GoHunt is a powerful, portable forensic analysis tool that uses eBPF (Extended Berkeley Packet Filter) with CO-RE (Compile Once - Run Everywhere) to detect sophisticated rootkit techniques on Linux systems. The tool compiles into a single static binary with no runtime dependencies, making it ideal for incident response and security auditing.

## Features

GoHunt implements three advanced detection techniques:

### 1. **System Call Table Integrity Check**
- Detects `sys_call_table` hooking by rootkits
- Compares kernel memory with expected values from `/proc/kallsyms`
- Uses kprobes to safely read kernel memory
- **Rootkit Technique Detected**: Syscall table modification

### 2. **Hidden Kernel Module Detection**
- Finds kernel modules hidden from `lsmod` and `/sys/module`
- Uses BPF iterators to traverse the kernel's internal module list
- Compares kernel ground truth with user-space visibility
- **Rootkit Technique Detected**: Module list manipulation (list_del)

### 3. **Hidden File Detection in PATH**
- Detects executable files hidden from directory listings
- Monitors `execve` syscalls via tracepoints
- Verifies file visibility from user-space
- **Rootkit Technique Detected**: `getdents64` hooking

## Architecture

```
┌─────────────────────────────────────────────────┐
│              GoHunt Binary                      │
│  (Static, Portable, Single Executable)          │
├─────────────────────────────────────────────────┤
│                                                 │
│  ┌──────────────┐  ┌──────────────┐            │
│  │  Check       │  │  Check       │            │
│  │  Interface   │  │  Runner      │            │
│  └──────────────┘  └──────────────┘            │
│                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌────────┤
│  │  Syscall     │  │  Modules     │  │Hidden  │
│  │  Check       │  │  Check       │  │Files   │
│  └──────┬───────┘  └──────┬───────┘  └───┬────┘
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
- `bpftool` (for generating `vmlinux.h`)
- `libbpf-dev` (for eBPF headers)

### Runtime Requirements
- Linux kernel 5.8+ with BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`)
- Root privileges (for loading eBPF programs)

### Installing Prerequisites

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y golang clang llvm libbpf-dev linux-headers-$(uname -r)
sudo apt-get install -y linux-tools-common linux-tools-$(uname -r)
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

### Step 1: Generate vmlinux.h

The `vmlinux.h` file contains kernel type definitions for CO-RE:

```bash
# Generate vmlinux.h from your running kernel
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

### Step 2: Generate eBPF Go Bindings

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

### Step 3: Build the Binary

```bash
# Static build for maximum portability
CGO_ENABLED=0 go build -ldflags="-s -w" -o gohunt .
```

Or use the Makefile:

```bash
make build
```

The resulting `gohunt` binary is completely standalone and can be copied to any Linux system with a compatible kernel.

## Usage

### Basic Usage

```bash
# Must be run as root
sudo ./gohunt
```

### Debug Mode

For detailed verbose output showing every step of the detection process:

```bash
# Enable debug mode
sudo ./gohunt -d
# or
sudo ./gohunt --debug
```

Debug mode provides detailed information about:
- eBPF program loading and CO-RE relocations
- Kernel symbol resolution
- BPF map configuration
- Kprobe/tracepoint attachment
- Ring buffer operations
- Event processing and parsing
- Resource cleanup

See [DEBUG.md](DEBUG.md) for complete debug mode documentation.

### Example Output

```
  ██████╗  ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗
 ██╔════╝ ██╔═══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝
 ██║  ███╗██║   ██║███████║██║   ██║██╔██╗ ██║   ██║   
 ██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   
 ╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   
  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   
                                                        
 eBPF-based Rootkit Detection Tool
 Version 1.0.0

Starting forensic analysis with 3 checks...

[1/3] Running: Syscall Table Integrity
        Detects sys_call_table hooking by comparing kernel memory with expected addresses
        ✅ sys_call_table entry for __x64_sys_getdents64 is intact (0xffffffff81234567) (0.12s)

[2/3] Running: Hidden Kernel Modules
        Detects kernel modules hidden from lsmod by comparing kernel module list with /sys/module
        ✅ All 145 kernel modules are visible (0.08s)

[3/3] Running: Hidden Files in PATH
        Detects executable files that are hidden from directory listings
  [*] Monitoring execve events for 5s...
        ✅ No hidden files detected (monitored 23 execve events) (5.11s)

======================================================================
SUMMARY REPORT
======================================================================
Total Checks: 3
  ✅ OK:         3
  🔍 SUSPICIOUS: 0
  ❌ ERROR:      0

Cleaning up...
======================================================================
✅ System appears clean - no rootkit activity detected
======================================================================
```

### Exit Codes

- `0`: All checks passed, no suspicious activity
- `1`: One or more checks failed with errors
- `2`: Suspicious activity detected (potential rootkit)

## Development

### Project Structure

```
gohunt/
├── main.go                 # Entry point and check runner
├── go.mod                  # Go module definition
├── checks/
│   ├── interface.go        # Check interface definition
│   ├── syscall.go          # Syscall table integrity check
│   ├── modules.go          # Hidden module detection
│   └── hidden_files.go     # Hidden file detection
└── bpf/
    ├── gohunt.bpf.c        # eBPF programs (C)
    └── vmlinux.h           # Kernel type definitions (generated)
```

### Adding New Checks

1. Implement the `Check` interface in a new file under `checks/`
2. Add your eBPF program to `bpf/gohunt.bpf.c` with a unique section name
3. Register your check in `main.go`
4. Run `go generate` to update eBPF bindings

Example:

```go
type MyCheck struct{}

func NewMyCheck() *MyCheck {
    return &MyCheck{}
}

func (c *MyCheck) Name() string {
    return "My Custom Check"
}

func (c *MyCheck) Description() string {
    return "Describes what this check does"
}

func (c *MyCheck) Run() (Result, error) {
    // Implementation
}

func (c *MyCheck) Cleanup() error {
    // Cleanup resources
}
```

## Makefile Targets

```bash
make help         # Show all available targets
make generate     # Generate vmlinux.h and eBPF bindings
make build        # Build the gohunt binary
make clean        # Remove built artifacts
make test         # Run tests
make install      # Install to /usr/local/bin
```

## Technical Details

### CO-RE (Compile Once - Run Everywhere)

GoHunt uses eBPF CO-RE, which allows the same eBPF bytecode to run on different kernel versions without recompilation. This is achieved through:

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

**Solution**: Run with `sudo ./gohunt`

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

## Acknowledgments

- The Cilium team for the excellent Go eBPF library
- The Linux kernel eBPF community
- Security researchers studying rootkit techniques

---

**⚠️ Disclaimer**: This tool is for legitimate security research and system administration only. Unauthorized access to computer systems is illegal.
