# GoHunt Development Guide

## Architecture Deep Dive

### eBPF CO-RE Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. Compile Time (Developer Machine)                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  bpf/gohunt.bpf.c  ──┐                                          │
│  bpf/vmlinux.h       │                                          │
│                      ├──> clang -target bpf ──> .o bytecode     │
│  BPF headers         │                                          │
│                      │                                          │
│  .o bytecode  ───────┴──> bpf2go ──> bpf_bpfel.go (embedded)    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. Build Time                                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  main.go                                                        │
│  checks/*.go        ├──> go build ──> gohunt (static binary)    │
│  bpf_bpfel.go       │                                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. Runtime (Target Machine - any kernel 5.8+)                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  gohunt binary runs                                             │
│       │                                                         │
│       ├──> cilium/ebpf loads embedded bytecode                  │
│       │                                                         │
│       └──> libbpf performs CO-RE relocations                    │
│            (adjusts field offsets for this kernel)              │
│                                                                 │
│  eBPF programs run in kernel                                    │
│       │                                                         │
│       └──> Data sent to userspace via ring buffers              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Check Lifecycle

Each check implements this lifecycle:

```go
check := NewXXXCheck()

// 1. Load eBPF programs
objs := &bpfObjects{}
loadBpfObjects(objs, nil)

// 2. Attach to kernel hooks
link := attachToKernel(objs.Program)

// 3. Configure maps (if needed)
objs.ConfigMap.Put(key, value)

// 4. Trigger/Monitor events
// ... check-specific logic ...

// 5. Collect results
results := readFromRingBuffer()

// 6. Analyze
findings := analyzeResults(results)

// 7. Cleanup
link.Close()
objs.Close()
```

## Adding a New Check

### Example: Network Connection Hiding Detection

Let's add a check that detects hidden network connections.

#### Step 1: Add eBPF Program

Add to `bpf/gohunt.bpf.c`:

```c
// Network connection hiding detection
struct netconn_event {
    __u32 pid;
    __u32 src_port;
    __u32 dst_port;
    __u32 src_ip;
    __u32 dst_ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} netconn_events SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int trace_tcp_connect(struct pt_regs *ctx)
{
    struct netconn_event *e;
    
    e = bpf_ringbuf_reserve(&netconn_events, sizeof(*e), 0);
    if (!e)
        return 0;
    
    // Fill event details
    e->pid = bpf_get_current_pid_tgid() >> 32;
    // ... extract connection details ...
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

#### Step 2: Create Check Implementation

Create `checks/netconn.go`:

```go
package checks

import (
    "fmt"
    "time"
    
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
)

type NetconnCheck struct {
    objs   *bpfObjects
    link   link.Link
    reader *ringbuf.Reader
}

func NewNetconnCheck() *NetconnCheck {
    return &NetconnCheck{}
}

func (c *NetconnCheck) Name() string {
    return "Hidden Network Connections"
}

func (c *NetconnCheck) Description() string {
    return "Detects network connections hidden from netstat/ss"
}

func (c *NetconnCheck) Run() (Result, error) {
    start := time.Now()
    result := Result{
        Status:   StatusOK,
        Findings: make([]Finding, 0),
    }
    
    // Load eBPF
    objs := &bpfObjects{}
    if err := loadBpfObjects(objs, nil); err != nil {
        result.Status = StatusError
        result.Error = err
        result.Duration = time.Since(start)
        return result, err
    }
    c.objs = objs
    
    // Attach kprobe
    kp, err := link.Kprobe("tcp_v4_connect", objs.TraceTcpConnect, nil)
    if err != nil {
        result.Status = StatusError
        result.Error = err
        result.Duration = time.Since(start)
        return result, err
    }
    c.link = kp
    
    // Open ring buffer
    rd, err := ringbuf.NewReader(objs.NetconnEvents)
    if err != nil {
        result.Status = StatusError
        result.Error = err
        result.Duration = time.Since(start)
        return result, err
    }
    c.reader = rd
    
    // Monitor and analyze...
    // ... your detection logic ...
    
    result.Duration = time.Since(start)
    return result, nil
}

func (c *NetconnCheck) Cleanup() error {
    if c.reader != nil {
        c.reader.Close()
    }
    if c.link != nil {
        c.link.Close()
    }
    if c.objs != nil {
        c.objs.Close()
    }
    return nil
}
```

#### Step 3: Register in main.go

```go
allChecks := []checks.Check{
    checks.NewSyscallCheck(),
    checks.NewModulesCheck(),
    checks.NewHiddenFilesCheck(),
    checks.NewNetconnCheck(),  // Add your check
}
```

#### Step 4: Regenerate and Build

```bash
make generate
make build
```

## Testing

### Unit Testing

Create `checks/syscall_test.go`:

```go
package checks

import (
    "testing"
)

func TestGetKernelSymbolAddr(t *testing.T) {
    addr, err := getKernelSymbolAddr("sys_call_table")
    if err != nil {
        t.Fatalf("Failed to find sys_call_table: %v", err)
    }
    
    if addr == 0 {
        t.Error("sys_call_table address is 0")
    }
    
    t.Logf("sys_call_table address: 0x%x", addr)
}
```

### Integration Testing

Create a test VM or container:

```bash
# Using QEMU
qemu-system-x86_64 \
    -kernel /boot/vmlinuz-$(uname -r) \
    -append "console=ttyS0" \
    -nographic \
    -enable-kvm
```

### Testing with Rootkit Simulators

**Warning**: Only test on isolated systems!

```bash
# Simulate syscall table hooking (for testing)
# This requires kernel module development
```

## Performance Considerations

### Ring Buffer Sizing

```c
// Adjust based on expected event rate
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256KB
} events SEC(".maps");
```

### eBPF Program Optimization

1. **Minimize map lookups**: Cache frequently accessed data
2. **Use inline helpers**: Mark frequently called functions `__always_inline`
3. **Limit loop iterations**: Use `#pragma unroll` carefully
4. **Reduce data copies**: Only copy necessary fields

### Go User-Space Optimization

1. **Batch ring buffer reads**: Process multiple events at once
2. **Use goroutines carefully**: eBPF calls must be synchronized
3. **Minimize allocations**: Reuse buffers where possible

## Debugging

### Enable eBPF Verifier Logs

```bash
# Set verifier log level
echo 1 > /proc/sys/kernel/bpf_log_level

# View kernel logs
dmesg | grep BPF
```

### Debug eBPF Programs

Add printk debugging:

```c
#include <bpf/bpf_helpers.h>

SEC("kprobe/my_function")
int my_probe(struct pt_regs *ctx)
{
    char msg[] = "Debug: entering probe\n";
    bpf_trace_printk(msg, sizeof(msg));
    return 0;
}
```

Read output:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### Debug Go Code

```bash
# Build with debug symbols
go build -gcflags="all=-N -l" -o gohunt .

# Run with delve
dlv exec ./gohunt
```

## Common Issues

### Issue: "invalid argument" when loading eBPF

**Cause**: eBPF verifier rejected the program

**Solution**: 
- Check verifier logs: `dmesg | tail`
- Simplify program logic
- Ensure BTF types are correct

### Issue: "no such device" 

**Cause**: Kernel doesn't support feature

**Solution**:
```bash
# Check kernel config
zcat /proc/config.gz | grep BPF
```

### Issue: CO-RE relocations failing

**Cause**: BTF info mismatch

**Solution**:
- Regenerate vmlinux.h on target system
- Check kernel has BTF: `ls /sys/kernel/btf/vmlinux`

## Security Best Practices

1. **Validate all input** from eBPF programs
2. **Limit privileged operations** to minimum necessary
3. **Use secure coding** practices (bounds checking, etc.)
4. **Monitor resource usage** to prevent DoS
5. **Test on multiple kernel versions**

## Resources

- [eBPF Documentation](https://ebpf.io/what-is-ebpf)
- [Cilium eBPF Guide](https://pkg.go.dev/github.com/cilium/ebpf)
- [Linux Kernel eBPF Docs](https://www.kernel.org/doc/html/latest/bpf/)
- [BPF CO-RE Reference](https://nakryiko.com/posts/bpf-portability-and-co-re/)

## Contributing Guidelines

1. Follow Go standard formatting (`go fmt`)
2. Add godoc comments to all exported functions
3. Include tests for new features
4. Update README with new checks
5. Test on multiple kernel versions (5.8, 5.15, 6.x)
6. Document any new kernel requirements
