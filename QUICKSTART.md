# Quick Start Guide

## For the Impatient

If you just want to build and run GoHunt as quickly as possible:

```bash
# 1. Install prerequisites (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y golang clang libbpf-dev linux-headers-$(uname -r) \
    linux-tools-common linux-tools-$(uname -r)

# 2. Build
./build.sh

# 3. Run (requires root)
sudo ./gohunt
```

## What Does It Do?

GoHunt runs three security checks:

1. **Syscall Table Check** (~0.1s)
   - Detects if system calls have been hooked
   - Checks: `getdents64` syscall

2. **Hidden Modules Check** (~0.1s)
   - Finds kernel modules hidden from `lsmod`
   - Compares kernel truth vs user-space visibility

3. **Hidden Files Check** (~5s)
   - Monitors program executions
   - Detects files that can execute but are invisible

Total runtime: ~5-6 seconds

## Understanding the Output

### Clean System
```
✅ sys_call_table entry for __x64_sys_getdents64 is intact
✅ All 145 kernel modules are visible
✅ No hidden files detected

System appears clean - no rootkit activity detected
```

### Compromised System
```
🔍 SUSPICIOUS: sys_call_table has been hooked!
   Expected 0xffffffff81234567, found 0xffffffff91234567
   
🔍 Module 'evil_rootkit' is loaded but hidden from /sys/module

⚠️ ALERT: Suspicious activity detected!
   Your system may be compromised.
```

## Exit Codes

- `0` - System is clean
- `1` - Checks failed with errors
- `2` - Rootkit detected

Use in scripts:
```bash
sudo ./gohunt
if [ $? -eq 2 ]; then
    echo "ALERT: Send notification!"
fi
```

## Minimal Example

Want to test just one check?

Edit `main.go`:
```go
allChecks := []checks.Check{
    checks.NewSyscallCheck(),  // Just this one
}
```

Rebuild:
```bash
go build -o gohunt .
sudo ./gohunt
```

## Common Questions

**Q: Why do I need root?**
A: eBPF programs require privileged access to attach to kernel functions.

**Q: Will this crash my system?**
A: No. eBPF programs are verified by the kernel and run safely in a sandbox.

**Q: How much overhead does it add?**
A: Negligible. eBPF is designed for high-performance monitoring.

**Q: Can rootkits detect GoHunt?**
A: Advanced rootkits could potentially detect it, but most cannot.

**Q: Does it work on my kernel?**
A: If you're running Linux 5.8+ with BTF support, yes.

Check your kernel:
```bash
uname -r  # Should be 5.8 or higher
ls /sys/kernel/btf/vmlinux  # Should exist
```

## Troubleshooting One-Liners

```bash
# Check kernel version
uname -r | awk -F. '{if ($1>=5 && $2>=8) print "✓ OK"; else print "✗ Too old"}'

# Check BTF support
[ -f /sys/kernel/btf/vmlinux ] && echo "✓ BTF enabled" || echo "✗ No BTF"

# Check if can read kallsyms (need root)
sudo grep sys_call_table /proc/kallsyms | head -1

# Quick build test
go version && clang --version && bpftool version
```

## Production Deployment

### As a Cron Job

```bash
# /etc/cron.daily/gohunt-check
#!/bin/bash
/usr/local/bin/gohunt > /var/log/gohunt-$(date +%Y%m%d).log 2>&1
if [ $? -eq 2 ]; then
    mail -s "ALERT: Rootkit detected!" admin@example.com < /var/log/gohunt-$(date +%Y%m%d).log
fi
```

### As a Systemd Service

Create `/etc/systemd/system/gohunt.service`:

```ini
[Unit]
Description=GoHunt Rootkit Detection
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/gohunt
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable:
```bash
sudo systemctl enable gohunt.timer
sudo systemctl start gohunt.timer
```

## Integration with Security Tools

### Splunk
```bash
sudo ./gohunt | logger -t gohunt -p local0.alert
```

### ELK Stack
```bash
sudo ./gohunt --json | curl -X POST localhost:9200/gohunt/_doc -d @-
```

### Prometheus (future feature)
```bash
sudo ./gohunt --metrics > /var/lib/node_exporter/gohunt.prom
```

## Next Steps

- Read [README.md](README.md) for full documentation
- Read [DEVELOPMENT.md](DEVELOPMENT.md) to add your own checks
- Star the project if you find it useful!
