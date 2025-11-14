# GoHunt Examples and Test Cases

## Example 1: Basic Rootkit Detection

### Scenario: Clean System

```bash
$ sudo ./gohunt

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
        Detects sys_call_table hooking by comparing kernel memory
        ✅ sys_call_table entry for __x64_sys_getdents64 is intact (0xffffffff81a34b60) (0.12s)

[2/3] Running: Hidden Kernel Modules
        Detects kernel modules hidden from lsmod
        ✅ All 145 kernel modules are visible (0.08s)

[3/3] Running: Hidden Files in PATH
        Detects executable files hidden from directory listings
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

## Example 2: Syscall Table Hooking Detected

### Scenario: Rootkit Hooks getdents64

```bash
$ sudo ./gohunt

[1/3] Running: Syscall Table Integrity
        Detects sys_call_table hooking by comparing kernel memory
        🔍 ALERT: sys_call_table has been hooked! Expected 0xffffffff81a34b60, found 0xffffffffc0123456 (0.12s)
          ⚠️  Syscall table entry for __x64_sys_getdents64 (syscall 217) has been modified
              - expected_address: 0xffffffff81a34b60
              - actual_address: 0xffffffffc0123456
              - difference: 0x3edee8f6

[2/3] Running: Hidden Kernel Modules
        ✅ All 145 kernel modules are visible (0.08s)

[3/3] Running: Hidden Files in PATH
        ✅ No hidden files detected (monitored 18 execve events) (5.09s)

======================================================================
SUMMARY REPORT
======================================================================
Total Checks: 3
  ✅ OK:         2
  🔍 SUSPICIOUS: 1
  ❌ ERROR:      0

DETAILED FINDINGS:
----------------------------------------------------------------------

Syscall Table Integrity:
  [1] Syscall table entry for __x64_sys_getdents64 (syscall 217) has been modified
      • expected_address: 0xffffffff81a34b60
      • actual_address: 0xffffffffc0123456
      • difference: 0x3edee8f6

Cleaning up...
======================================================================
⚠️  ALERT: Suspicious activity detected!
   Your system may be compromised. Review findings above.
======================================================================
```

**Exit Code**: 2

## Example 3: Hidden Kernel Module

### Scenario: Rootkit Unlinks Itself from Module List

```bash
$ sudo ./gohunt

[1/3] Running: Syscall Table Integrity
        ✅ sys_call_table entry for __x64_sys_getdents64 is intact (0xffffffff81a34b60) (0.11s)

[2/3] Running: Hidden Kernel Modules
        Detects kernel modules hidden from lsmod
        🔍 Found 1 hidden kernel module(s) (0.09s)
          ⚠️  Module 'rootkit_lkm' is loaded in kernel but hidden from /sys/module
              - module_name: rootkit_lkm
              - detection_type: hidden_from_sysfs

[3/3] Running: Hidden Files in PATH
        ✅ No hidden files detected (monitored 20 execve events) (5.10s)

======================================================================
SUMMARY REPORT
======================================================================
Total Checks: 3
  ✅ OK:         2
  🔍 SUSPICIOUS: 1
  ❌ ERROR:      0

DETAILED FINDINGS:
----------------------------------------------------------------------

Hidden Kernel Modules:
  [1] Module 'rootkit_lkm' is loaded in kernel but hidden from /sys/module
      • module_name: rootkit_lkm
      • detection_type: hidden_from_sysfs
```

## Example 4: Hidden File Detection

### Scenario: Backdoor Binary Hidden from ls

```bash
$ sudo ./gohunt

[1/3] Running: Syscall Table Integrity
        ✅ sys_call_table entry is intact (0.11s)

[2/3] Running: Hidden Kernel Modules
        ✅ All 146 kernel modules are visible (0.08s)

[3/3] Running: Hidden Files in PATH
        Detects executable files hidden from directory listings
  [*] Monitoring execve events for 5s...
        🔍 Found 2 hidden file(s) in PATH directories (monitored 45 execve events) (5.12s)
          ⚠️  File '/bin/.backdoor' was executed but is hidden from directory listings
              - file_path: /bin/.backdoor
              - pid: 12345
              - detection_type: hidden_executable
              - stat_error: stat /bin/.backdoor: no such file or directory
          ⚠️  File '/usr/bin/evil' was executed but is hidden from directory listings
              - file_path: /usr/bin/evil
              - pid: 12347
              - detection_type: hidden_executable
              - stat_error: stat /usr/bin/evil: no such file or directory

======================================================================
SUMMARY REPORT
======================================================================
Total Checks: 3
  ✅ OK:         2
  🔍 SUSPICIOUS: 1
  ❌ ERROR:      0
```

## Example 5: Multiple Issues Detected

### Scenario: Fully Compromised System

```bash
$ sudo ./gohunt

[1/3] Running: Syscall Table Integrity
        🔍 ALERT: sys_call_table has been hooked! (0.11s)
          ⚠️  Syscall table entry for __x64_sys_getdents64 has been modified

[2/3] Running: Hidden Kernel Modules
        🔍 Found 2 hidden kernel module(s) (0.09s)
          ⚠️  Module 'rootkit_main' is loaded in kernel but hidden from /sys/module
          ⚠️  Module 'rootkit_net' is loaded in kernel but hidden from /sys/module

[3/3] Running: Hidden Files in PATH
        🔍 Found 3 hidden file(s) in PATH directories (5.13s)
          ⚠️  File '/bin/.backdoor' was executed but is hidden
          ⚠️  File '/usr/bin/keylogger' was executed but is hidden
          ⚠️  File '/sbin/rootshell' was executed but is hidden

======================================================================
SUMMARY REPORT
======================================================================
Total Checks: 3
  ✅ OK:         0
  🔍 SUSPICIOUS: 3
  ❌ ERROR:      0

DETAILED FINDINGS:
----------------------------------------------------------------------

Syscall Table Integrity:
  [1] Syscall table entry for __x64_sys_getdents64 (syscall 217) has been modified
      • expected_address: 0xffffffff81a34b60
      • actual_address: 0xffffffffc0123456
      • difference: 0x3edee8f6

Hidden Kernel Modules:
  [1] Module 'rootkit_main' is loaded in kernel but hidden from /sys/module
      • module_name: rootkit_main
      • detection_type: hidden_from_sysfs
  [2] Module 'rootkit_net' is loaded in kernel but hidden from /sys/module
      • module_name: rootkit_net
      • detection_type: hidden_from_sysfs

Hidden Files in PATH:
  [1] File '/bin/.backdoor' was executed but is hidden from directory listings
      • file_path: /bin/.backdoor
      • pid: 12345
      • detection_type: hidden_executable
  [2] File '/usr/bin/keylogger' was executed but is hidden from directory listings
      • file_path: /usr/bin/keylogger
      • pid: 12346
      • detection_type: hidden_executable
  [3] File '/sbin/rootshell' was executed but is hidden from directory listings
      • file_path: /sbin/rootshell
      • pid: 12348
      • detection_type: hidden_executable

======================================================================
⚠️  ALERT: Suspicious activity detected!
   Your system may be compromised. Review findings above.
======================================================================
```

**Exit Code**: 2

## Example 6: Error Conditions

### Scenario: Missing Kernel Symbols

```bash
$ sudo ./gohunt

[1/3] Running: Syscall Table Integrity
        ❌ failed to find __x64_sys_getdents64: symbol not found in /proc/kallsyms (0.01s)
          ⚠️  Error: failed to find __x64_sys_getdents64: symbol not found in /proc/kallsyms

[2/3] Running: Hidden Kernel Modules
        ✅ All 145 kernel modules are visible (0.08s)

[3/3] Running: Hidden Files in PATH
        ✅ No hidden files detected (5.10s)

======================================================================
SUMMARY REPORT
======================================================================
Total Checks: 3
  ✅ OK:         2
  🔍 SUSPICIOUS: 0
  ❌ ERROR:      1

======================================================================
⚠️  WARNING: Some checks failed to complete
======================================================================
```

**Exit Code**: 1

## Example 7: Using in Scripts

### Bash Script Integration

```bash
#!/bin/bash

LOG_FILE="/var/log/gohunt-$(date +%Y%m%d-%H%M%S).log"

echo "Running GoHunt rootkit detection..."
sudo /usr/local/bin/gohunt > "$LOG_FILE" 2>&1

EXIT_CODE=$?

case $EXIT_CODE in
    0)
        echo "✓ System is clean"
        ;;
    1)
        echo "⚠ Some checks failed - see $LOG_FILE"
        cat "$LOG_FILE" | mail -s "GoHunt: Check Failures" admin@example.com
        ;;
    2)
        echo "🚨 ROOTKIT DETECTED - see $LOG_FILE"
        cat "$LOG_FILE" | mail -s "ALERT: Rootkit Detected!" security@example.com
        # Trigger incident response
        /opt/scripts/incident-response.sh
        ;;
esac

exit $EXIT_CODE
```

### Python Integration

```python
#!/usr/bin/env python3

import subprocess
import json
import sys

def run_gohunt():
    """Run gohunt and parse output"""
    try:
        result = subprocess.run(
            ['sudo', '/usr/local/bin/gohunt'],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        return {
            'exit_code': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr
        }
    except subprocess.TimeoutExpired:
        return {'exit_code': -1, 'error': 'timeout'}

def main():
    print("Running GoHunt...")
    result = run_gohunt()
    
    if result['exit_code'] == 0:
        print("✓ System is clean")
    elif result['exit_code'] == 1:
        print("⚠ Some checks failed")
        print(result['stderr'])
    elif result['exit_code'] == 2:
        print("🚨 ROOTKIT DETECTED!")
        print(result['stdout'])
        # Send to SIEM
        send_to_siem(result)
    
    return result['exit_code']

if __name__ == '__main__':
    sys.exit(main())
```

## Example 8: Automated Monitoring

### Systemd Timer

Create `/etc/systemd/system/gohunt.timer`:

```ini
[Unit]
Description=Run GoHunt hourly
Requires=gohunt.service

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h
Unit=gohunt.service

[Install]
WantedBy=timers.target
```

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
User=root

# On detection, trigger alert script
ExecStartPost=/bin/bash -c 'if [ $EXIT_CODE -eq 2 ]; then /opt/scripts/alert.sh; fi'

[Install]
WantedBy=multi-user.target
```

Enable:
```bash
sudo systemctl daemon-reload
sudo systemctl enable gohunt.timer
sudo systemctl start gohunt.timer
```

Check status:
```bash
sudo systemctl status gohunt.timer
sudo journalctl -u gohunt.service -f
```

## Testing GoHunt (Safe)

### Test 1: Verify Syscall Check Works

```bash
# Check current syscall table
sudo grep sys_call_table /proc/kallsyms
sudo grep __x64_sys_getdents64 /proc/kallsyms

# Run GoHunt - should show OK
sudo ./gohunt
```

### Test 2: Verify Module Detection Works

```bash
# List current modules
lsmod | wc -l

# Run GoHunt - should show same count
sudo ./gohunt
```

### Test 3: Verify Hidden File Detection

```bash
# Generate some execve events
ls /bin/* > /dev/null
find /usr/bin -type f -executable | head -20 | xargs -n1 -I{} sh -c "file {}"

# Run GoHunt - should detect these executions
sudo ./gohunt
```

## Performance Benchmarks

```bash
# Syscall check: ~100ms
time sudo ./gohunt  # Focus on check 1

# Module check: ~80ms  
# Hidden files: ~5000ms (configurable)

# Total: ~5.2 seconds
```

## Next Steps

- Integrate with your monitoring system
- Set up automated scanning
- Customize detection thresholds
- Add custom checks for your environment
