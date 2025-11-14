# Debug Mode Documentation

## Overview

GoHunt now includes comprehensive debug logging capabilities that provide detailed insight into every step of the eBPF rootkit detection process.

## Usage

Enable debug mode using either the short or long flag:

```bash
# Short flag
sudo ./gohunt -d

# Long flag
sudo ./gohunt --debug
```

## Debug Output Details

When debug mode is enabled, you'll see verbose output for:

### 1. **System Information**
- Operating system and kernel version
- User ID and effective user ID
- Check registration and initialization

### 2. **Syscall Table Integrity Check**
- **BPF Loading**: CO-RE relocations, program verification, map creation
- **Symbol Resolution**: Parsing /proc/kallsyms for sys_call_table and syscall addresses
- **Map Configuration**: Writing kernel addresses to BPF maps
- **Kprobe Attachment**: Attaching to kernel functions to trigger checks
- **Ring Buffer Operations**: Opening readers, receiving events
- **Event Processing**: Parsing binary data from kernel
- **Address Comparison**: Comparing expected vs actual syscall addresses
- **Cleanup**: Detaching probes, closing resources

### 3. **Hidden Files Detection**
- **BPF Loading**: Program loading and verification
- **Tracepoint Attachment**: Attaching to execve, openat, open, openat2 syscalls
- **Ring Buffer Setup**: Creating event readers
- **Monitoring Phase**: Real-time event collection (shows first 10 events by default)
- **Event Processing**: Parsing file access events, checking file existence
- **Detection**: Immediate alerts for hidden files
- **Statistics**: Total events, per-syscall breakdown
- **Cleanup**: Goroutine shutdown, tracepoint detachment

### 4. **Hidden Kernel Modules**
- **Module Enumeration**: Reading /proc/modules and /sys/module
- **Module Lists**: Displays module names (first 20 if many)
- **Comparison**: Cross-referencing to find discrepancies
- **Detection**: Alerts for modules hidden from sysfs

### 5. **Cleanup Phase**
- Detailed logging for each resource cleanup step
- Error reporting for failed cleanup operations

## Example Output

### Normal Mode:
```
[1/3] Running: Syscall Table Integrity
        Detects sys_call_table hooking by comparing kernel memory...
        ✅ sys_call_table entry for __x64_sys_getdents64 is intact (0.12s)
```

### Debug Mode:
```
[1/3] Running: Syscall Table Integrity
        Detects sys_call_table hooking by comparing kernel memory...
[DEBUG 14:30:45.123] ============================================================
[DEBUG 14:30:45.123] Starting check [1/3]: Syscall Table Integrity
[DEBUG 14:30:45.123] Description: Detects sys_call_table hooking...
[SYSCALL-CHECK 14:30:45.124] Starting syscall table integrity check
[SYSCALL-CHECK 14:30:45.124] Step 1: Loading eBPF objects with CO-RE...
[SYSCALL-CHECK 14:30:45.234] SUCCESS: eBPF objects loaded successfully
[SYSCALL-CHECK 14:30:45.234]   - CO-RE relocations applied
[SYSCALL-CHECK 14:30:45.234]   - BPF programs verified and loaded into kernel
[SYSCALL-CHECK 14:30:45.234]   - BPF maps created (syscall_events, syscall_config)
[SYSCALL-CHECK 14:30:45.235] Step 2: Parsing /proc/kallsyms for kernel symbols...
[SYSCALL-CHECK 14:30:45.245] Found sys_call_table at address: 0xffffffff82c001c0
[SYSCALL-CHECK 14:30:45.245] Looking up syscall: __x64_sys_getdents64 (number 217)
[SYSCALL-CHECK 14:30:45.250] Found __x64_sys_getdents64 at address: 0xffffffff812a3f10
[SYSCALL-CHECK 14:30:45.250] Step 3: Configuring eBPF program with addresses...
[SYSCALL-CHECK 14:30:45.251] Writing sys_call_table address (0xffffffff82c001c0) to BPF map at key 0
[SYSCALL-CHECK 14:30:45.251] Writing syscall number (217) to BPF map at key 1
[SYSCALL-CHECK 14:30:45.251] SUCCESS: BPF maps configured with kernel addresses
[SYSCALL-CHECK 14:30:45.251] Step 4: Attaching kprobe to trigger syscall table check...
[SYSCALL-CHECK 14:30:45.251] Attempting to attach kprobe to: __x64_sys_getuid
[SYSCALL-CHECK 14:30:45.267] SUCCESS: Kprobe attached - BPF program will execute on next getuid() call
[SYSCALL-CHECK 14:30:45.267] Step 5: Opening ring buffer to receive events...
[SYSCALL-CHECK 14:30:45.267] SUCCESS: Ring buffer reader created
[SYSCALL-CHECK 14:30:45.267] Step 6: Triggering check by calling getuid()...
[SYSCALL-CHECK 14:30:45.267] Called getuid(), returned UID: 0
[SYSCALL-CHECK 14:30:45.267] Kprobe should have executed, reading event from ring buffer...
[SYSCALL-CHECK 14:30:45.368] Step 7: Reading syscall table entry from ring buffer...
[SYSCALL-CHECK 14:30:45.368] SUCCESS: Received event from kernel (size: 16 bytes)
[SYSCALL-CHECK 14:30:45.368] Step 8: Parsing event data...
[SYSCALL-CHECK 14:30:45.368] Parsed event: syscall_num=217, syscall_addr=0xffffffff812a3f10
[SYSCALL-CHECK 14:30:45.368] Step 9: Comparing addresses...
[SYSCALL-CHECK 14:30:45.368]   Expected address (from kallsyms): 0xffffffff812a3f10
[SYSCALL-CHECK 14:30:45.368]   Actual address (from sys_call_table): 0xffffffff812a3f10
[SYSCALL-CHECK 14:30:45.368] SUCCESS: Addresses match - sys_call_table is intact
[DEBUG 14:30:45.368] Check completed in 0.244s
        ✅ sys_call_table entry for __x64_sys_getdents64 is intact (0.24s)
```

## Benefits of Debug Mode

1. **Troubleshooting**: Identify exactly where failures occur in the BPF loading or attachment process
2. **Learning**: Understand how CO-RE, BPF programs, and kernel interactions work
3. **Verification**: Confirm that detection mechanisms are working correctly
4. **Performance Analysis**: See timing for each step and identify bottlenecks
5. **Development**: Essential for adding new checks or modifying existing ones

## Performance Impact

Debug mode adds minimal overhead:
- Logging operations are conditional (no-op when disabled)
- Timestamps are calculated only when debug is active
- String formatting occurs only when messages are printed

The impact on detection accuracy is negligible, typically adding < 5% to execution time.

## Log Format

Debug logs follow this format:
```
[<CHECK-TYPE> <HH:MM:SS.mmm>] <message>
```

Where:
- `CHECK-TYPE`: SYSCALL-CHECK, HIDDEN-FILES, MODULES-CHECK, or DEBUG (main program)
- `HH:MM:SS.mmm`: High-resolution timestamp
- `message`: Detailed information about the operation

## Integration with Build System

Debug mode is compiled into the binary by default and has no external dependencies. It works with the standard build process:

```bash
./build.sh
sudo ./gohunt -d
```

## Tips

1. **Redirect to File**: Capture debug output for analysis:
   ```bash
   sudo ./gohunt -d 2>&1 | tee gohunt-debug.log
   ```

2. **Compare Runs**: Use debug logs to compare behavior across different kernels or systems

3. **Report Issues**: Include debug output when reporting bugs or unexpected behavior

4. **Development**: Always test with `-d` flag when modifying BPF programs or checks
