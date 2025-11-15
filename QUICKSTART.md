````markdown
# Zygarde - Quick Start Guide

## For the Impatient

If you just want to build and run Zygarde as quickly as possible:

```bash
# 1. Install prerequisites (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y golang clang libbpf-dev linux-headers-$(uname -r) \
    linux-tools-common linux-tools-$(uname -r)

# 2. Build
./build.sh

# 3. Deploy Cells (requires root)
sudo ./zygarde
```

## What Does It Do?

Zygarde deploys three specialized Cells for ecosystem monitoring:

1. **Syscall Integrity Cell** (~0.1s)
   - Detects if system calls have been hooked
   - Checks: `getdents64` syscall integrity

2. **Module Visibility Cell** (~0.1s)
   - Finds kernel modules hidden from `lsmod`
   - Compares kernel truth vs user-space visibility

3. **File Visibility Cell** (~5s)
   - Monitors program executions
   - Detects files that can execute but are invisible

Total runtime: ~5-6 seconds

## Understanding the Output

### Ecosystem Stable (Clean System)
```
[+] sys_call_table entry for __x64_sys_getdents64 is intact
[+] All 145 kernel modules are visible
[+] No hidden files detected

[+] Ecosystem stable - no threats detected
   Zygarde Cells report: All clear
```

### Threat Detected (Compromised System)
```
[*] SUSPICIOUS: sys_call_table has been hooked!
   Expected 0xffffffff81234567, found 0xffffffff91234567
   
[*] Module 'evil_rootkit' is loaded but hidden from /sys/module

[*] ECOSYSTEM THREAT DETECTED!
   Zygarde Complete Forme activation recommended.
   Review findings above and take immediate action.
```

## Exit Codes

- `0` - Ecosystem is stable (no threats)
- `1` - Some Cells failed with errors
- `2` - Threat detected (rootkit activity)

Use in scripts:
```bash
sudo ./zygarde
if [ $? -eq 2 ]; then
    echo "ALERT: Ecosystem threatened! Send notification!"
fi
```

## Minimal Example

Want to deploy just one Cell?

Edit `main.go`:
```go
allCells := []checks.Check{
    checks.NewSyscallCheck(),  // Just this Cell
}
```

Rebuild:
```bash
go build -o zygarde .
sudo ./zygarde
```

## Common Questions

**Q: Why do I need root?**
A: eBPF programs require privileged access to attach to kernel functions and monitor the ecosystem.

**Q: Will this crash my system?**
A: No. eBPF programs are verified by the kernel and run safely in a sandbox.

**Q: How much overhead does it add?**
A: Negligible. eBPF is designed for high-performance monitoring with minimal impact.

**Q: Can rootkits detect Zygarde?**
A: Advanced rootkits could potentially detect it, but most cannot. Zygarde operates deep within the kernel like the Cells monitoring the ecosystem.

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
uname -r | awk -F. '{if ($1>=5 && $2>=8) print "[+] OK"; else print "[-] Too old"}'

# Check BTF support
[ -f /sys/kernel/btf/vmlinux ] && echo "[+] BTF enabled" || echo "[-] No BTF"

# Check if can read kallsyms (need root)
sudo grep sys_call_table /proc/kallsyms | head -1

# Quick build test
go version && clang --version && bpftool version
```

## Production Deployment

### As a Cron Job

```bash
# /etc/cron.daily/zygarde-check
#!/bin/bash
/usr/local/bin/zygarde > /var/log/zygarde-$(date +%Y%m%d).log 2>&1
if [ $? -eq 2 ]; then
    mail -s "ALERT: Ecosystem threat detected!" admin@example.com < /var/log/zygarde-$(date +%Y%m%d).log
fi
```

Make it executable:
```bash
sudo chmod +x /etc/cron.daily/zygarde-check
```

### As a Systemd Service

Create `/etc/systemd/system/zygarde.service`:

```ini
[Unit]
Description=Zygarde Ecosystem Guardian
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/zygarde
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Create `/etc/systemd/system/zygarde.timer`:

```ini
[Unit]
Description=Zygarde Daily Ecosystem Check

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Enable:
```bash
sudo systemctl daemon-reload
sudo systemctl enable zygarde.timer
sudo systemctl start zygarde.timer

# Check status
sudo systemctl status zygarde.timer
```

## Integration with Security Tools

### Splunk
```bash
sudo ./zygarde | logger -t zygarde -p local0.alert
```

### ELK Stack (if JSON output implemented)
```bash
sudo ./zygarde --json 2>/dev/null | curl -X POST localhost:9200/zygarde/_doc -H 'Content-Type: application/json' -d @-
```

### Simple Logging
```bash
sudo ./zygarde 2>&1 | tee -a /var/log/zygarde.log
```

## Automation Examples

### Alert on Threat Detection
```bash
#!/bin/bash
sudo ./zygarde > /tmp/zygarde-scan.log 2>&1
EXIT_CODE=$?

if [ $EXIT_CODE -eq 2 ]; then
    # Threat detected - activate Complete Forme response
    echo "Subject: CRITICAL: Zygarde Threat Detection" > /tmp/zygarde-alert.txt
    echo "Ecosystem threat detected on $(hostname)" >> /tmp/zygarde-alert.txt
    echo "" >> /tmp/zygarde-alert.txt
    cat /tmp/zygarde-scan.log >> /tmp/zygarde-alert.txt
    
    # Send alert (choose your method)
    mail -s "THREAT ALERT" security@example.com < /tmp/zygarde-alert.txt
    # or
    curl -X POST https://hooks.slack.com/... -d @/tmp/zygarde-alert.txt
fi
```

### Monitoring Loop
```bash
#!/bin/bash
# Continuous monitoring (use with caution in production)
while true; do
    echo "[$(date)] Deploying Zygarde Cells..."
    sudo ./zygarde
    
    if [ $? -eq 2 ]; then
        echo "THREAT DETECTED - Check logs immediately"
        break
    fi
    
    echo "Ecosystem stable. Waiting 1 hour..."
    sleep 3600
done
```

## Debug Mode

For troubleshooting or understanding Cell operations:

```bash
sudo ./zygarde --debug
```

This shows:
- Cell activation details
- eBPF program loading
- Kernel symbol resolution
- Event processing
- Resource cleanup

Perfect for understanding how each Cell operates or diagnosing issues.

## Performance Tips

1. **Normal Scans**: Run daily via cron
2. **Intensive Monitoring**: Use with caution - File Visibility Cell runs for 5 seconds
3. **Quick Check**: Deploy only Syscall and Module Cells if time-constrained
4. **Resource Usage**: Minimal - primarily during the 5-second monitoring window

## Next Steps

- Read [README.md](README.md) for complete documentation
- Read [DEVELOPMENT.md](DEVELOPMENT.md) to add your own Cells
- Check [MIGRATION.md](MIGRATION.md) if upgrading from GoHunt
- Star the project if you find it useful!

---

<div align="center">

*"When the ecosystem is threatened, the Cells gather to protect."*

**Guardian of the Kernel** | **Order Forme Activated**

</div>
````
