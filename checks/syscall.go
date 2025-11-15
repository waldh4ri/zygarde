package checks

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64,arm64 bpf ../bpf/zygarde.bpf.c -- -I../bpf

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// SyscallCheck verifies the integrity of the sys_call_table
// by comparing kernel memory with /proc/kallsyms values
type SyscallCheck struct {
	objs   *bpfObjects
	link   link.Link
	reader *ringbuf.Reader
	debug  bool
}

// debugLog prints a message only if debug mode is enabled
func (c *SyscallCheck) debugLog(format string, args ...interface{}) {
	if c.debug {
		timestamp := time.Now().Format("15:04:05.000")
		msg := fmt.Sprintf(format, args...)
		log.Printf("[SYSCALL-CHECK %s] %s", timestamp, msg)
	}
}

// syscallEvent matches the C structure in the eBPF program
type syscallEvent struct {
	SyscallAddr uint64
	SyscallNum  uint32
	_           uint32 // padding
}

// NewSyscallCheck creates a new syscall integrity check
func NewSyscallCheck() *SyscallCheck {
	return &SyscallCheck{}
}

// SetDebug enables or disables debug mode
func (c *SyscallCheck) SetDebug(debug bool) {
	c.debug = debug
}

// Name returns the check name
func (c *SyscallCheck) Name() string {
	return "Syscall Table Integrity"
}

// Description returns what this check does
func (c *SyscallCheck) Description() string {
	return "Detects sys_call_table hooking by comparing kernel memory with expected addresses from /proc/kallsyms"
}

// Run executes the syscall integrity check
func (c *SyscallCheck) Run() (Result, error) {
	start := time.Now()
	result := Result{
		Status:   StatusOK,
		Findings: make([]Finding, 0),
	}

	c.debugLog("Starting syscall table integrity check")
	c.debugLog("Step 1: Loading eBPF objects with CO-RE...")

	// Load the eBPF program
	objs := &bpfObjects{}
	if err := loadBpfObjects(objs, nil); err != nil {
		c.debugLog("ERROR: Failed to load eBPF objects: %v", err)
		result.Status = StatusError
		result.Error = fmt.Errorf("failed to load eBPF objects: %w", err)
		result.Duration = time.Since(start)
		return result, err
	}
	c.objs = objs
	c.debugLog("SUCCESS: eBPF objects loaded successfully")
	c.debugLog("  - CO-RE relocations applied")
	c.debugLog("  - BPF programs verified and loaded into kernel")
	c.debugLog("  - BPF maps created (syscall_events, syscall_config)")

	c.debugLog("Step 2: Parsing /proc/kallsyms for kernel symbols...")

	// Parse /proc/kallsyms to get expected addresses
	sysCallTableAddr, err := getKernelSymbolAddr("sys_call_table")
	if err != nil {
		c.debugLog("ERROR: Failed to find sys_call_table: %v", err)
		result.Status = StatusError
		result.Error = fmt.Errorf("failed to find sys_call_table: %w", err)
		result.Duration = time.Since(start)
		return result, err
	}
	c.debugLog("Found sys_call_table at address: 0x%x", sysCallTableAddr)

	// Define critical syscalls to check
	type syscallInfo struct {
		name        string
		altName     string
		number      uint64
		description string
	}

	syscallsToCheck := []syscallInfo{
		{
			name:        "__x64_sys_getdents64",
			altName:     "sys_getdents64",
			number:      217,
			description: "Directory listing (64-bit)",
		},
		{
			name:        "__x64_sys_getdents",
			altName:     "sys_getdents",
			number:      78,
			description: "Directory listing (32-bit)",
		},
		{
			name:        "__x64_sys_kill",
			altName:     "sys_kill",
			number:      62,
			description: "Process signaling",
		},
		{
			name:        "__x64_sys_read",
			altName:     "sys_read",
			number:      0,
			description: "File reading",
		},
	}

	c.debugLog("Step 3: Opening ring buffer to receive events...")

	// Open the ring buffer to receive events
	rd, err := ringbuf.NewReader(objs.SyscallEvents)
	if err != nil {
		c.debugLog("ERROR: Failed to open ring buffer: %v", err)
		result.Status = StatusError
		result.Error = fmt.Errorf("failed to open ring buffer: %w", err)
		result.Duration = time.Since(start)
		return result, err
	}
	c.reader = rd
	c.debugLog("SUCCESS: Ring buffer reader created")

	c.debugLog("Step 4: Attaching kprobe to trigger syscall table check...")

	// Attach the kprobe to sys_getuid (frequent, harmless syscall)
	c.debugLog("Attempting to attach kprobe to: __x64_sys_getuid")
	kp, err := link.Kprobe("__x64_sys_getuid", objs.CheckSyscallTable, nil)
	if err != nil {
		// Try alternative symbol
		c.debugLog("Failed to attach to __x64_sys_getuid, trying alternative: sys_getuid")
		kp, err = link.Kprobe("sys_getuid", objs.CheckSyscallTable, nil)
		if err != nil {
			c.debugLog("ERROR: Failed to attach kprobe: %v", err)
			result.Status = StatusError
			result.Error = fmt.Errorf("failed to attach kprobe: %w", err)
			result.Duration = time.Since(start)
			return result, err
		}
	}
	c.link = kp
	c.debugLog("SUCCESS: Kprobe attached - BPF program will execute on next getuid() call")

	// Check each critical syscall
	checkedCount := 0
	for _, syscallToCheck := range syscallsToCheck {
		c.debugLog("Step %d: Checking syscall: %s (number %d) - %s", 5+checkedCount*5, syscallToCheck.name, syscallToCheck.number, syscallToCheck.description)

		// Look up the expected address
		syscallName := syscallToCheck.name
		syscallNum := syscallToCheck.number
		c.debugLog("Looking up syscall: %s (number %d)", syscallName, syscallNum)
		expectedAddr, err := getKernelSymbolAddr(syscallName)
		if err != nil {
			// Try alternative name
			c.debugLog("Symbol %s not found, trying alternative: %s", syscallName, syscallToCheck.altName)
			syscallName = syscallToCheck.altName
			expectedAddr, err = getKernelSymbolAddr(syscallName)
			if err != nil {
				c.debugLog("WARNING: Failed to find %s: %v (skipping)", syscallName, err)
				checkedCount++
				continue
			}
		}
		c.debugLog("Found %s at address: 0x%x", syscallName, expectedAddr)

		c.debugLog("Configuring eBPF program with addresses...")

		// Configure the eBPF program with sys_call_table address and syscall number
		key0 := uint32(0)
		key1 := uint32(1)
		c.debugLog("Writing sys_call_table address (0x%x) to BPF map at key 0", sysCallTableAddr)
		if err := objs.SyscallConfig.Put(&key0, &sysCallTableAddr); err != nil {
			c.debugLog("ERROR: Failed to configure sys_call_table address: %v", err)
			result.Status = StatusError
			result.Error = fmt.Errorf("failed to configure sys_call_table address: %w", err)
			result.Duration = time.Since(start)
			return result, err
		}
		c.debugLog("Writing syscall number (%d) to BPF map at key 1", syscallNum)
		if err := objs.SyscallConfig.Put(&key1, &syscallNum); err != nil {
			c.debugLog("ERROR: Failed to configure syscall number: %v", err)
			result.Status = StatusError
			result.Error = fmt.Errorf("failed to configure syscall number: %w", err)
			result.Duration = time.Since(start)
			return result, err
		}
		c.debugLog("SUCCESS: BPF maps configured with kernel addresses")

		c.debugLog("Triggering check by calling getuid()...")

		// Trigger the check by calling getuid (which will trigger our kprobe)
		uid := os.Getuid()
		c.debugLog("Called getuid(), returned UID: %d", uid)
		c.debugLog("Kprobe should have executed, reading event from ring buffer...")

		// Wait a bit for the event to be processed
		time.Sleep(100 * time.Millisecond)

		c.debugLog("Reading syscall table entry from ring buffer...")

		// Read the event from the ring buffer
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				c.debugLog("ERROR: Ring buffer closed unexpectedly")
				result.Status = StatusError
				result.Error = fmt.Errorf("ring buffer closed unexpectedly")
				result.Duration = time.Since(start)
				return result, err
			}
			c.debugLog("ERROR: Failed to read from ring buffer: %v", err)
			result.Status = StatusError
			result.Error = fmt.Errorf("failed to read from ring buffer: %w", err)
			result.Duration = time.Since(start)
			return result, err
		}
		c.debugLog("SUCCESS: Received event from kernel (size: %d bytes)", len(record.RawSample))

		c.debugLog("Parsing event data...")

		// Parse the event
		var event syscallEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			c.debugLog("ERROR: Failed to parse event: %v", err)
			result.Status = StatusError
			result.Error = fmt.Errorf("failed to parse event: %w", err)
			result.Duration = time.Since(start)
			return result, err
		}
		c.debugLog("Parsed event: syscall_num=%d, syscall_addr=0x%x", event.SyscallNum, event.SyscallAddr)

		c.debugLog("Comparing addresses...")
		c.debugLog("  Expected address (from kallsyms): 0x%x", expectedAddr)
		c.debugLog("  Actual address (from sys_call_table): 0x%x", event.SyscallAddr)

		// Compare addresses
		if event.SyscallAddr != expectedAddr {
			c.debugLog("ALERT: Address mismatch detected! Difference: 0x%x", int64(event.SyscallAddr)-int64(expectedAddr))
			result.Status = StatusSuspicious
			result.Findings = append(result.Findings, Finding{
				Description: fmt.Sprintf("Syscall table entry for %s (syscall %d) has been modified", syscallName, syscallNum),
				Details: map[string]string{
					"syscall":          syscallName,
					"syscall_number":   fmt.Sprintf("%d", syscallNum),
					"description":      syscallToCheck.description,
					"expected_address": fmt.Sprintf("0x%x", expectedAddr),
					"actual_address":   fmt.Sprintf("0x%x", event.SyscallAddr),
					"difference":       fmt.Sprintf("0x%x", int64(event.SyscallAddr)-int64(expectedAddr)),
				},
			})
		} else {
			c.debugLog("SUCCESS: Addresses match - syscall entry is intact")
		}

		checkedCount++
	}

	// Generate final result message
	if result.Status == StatusSuspicious {
		result.Message = fmt.Sprintf("ALERT: %d syscall(s) hooked in sys_call_table!", len(result.Findings))
	} else {
		result.Message = fmt.Sprintf("All %d checked syscalls are intact", checkedCount)
	}

	result.Duration = time.Since(start)
	return result, nil
}

// Cleanup closes the eBPF resources
func (c *SyscallCheck) Cleanup() error {
	c.debugLog("Starting cleanup...")
	var errs []error

	if c.reader != nil {
		c.debugLog("Closing ring buffer reader...")
		if err := c.reader.Close(); err != nil {
			c.debugLog("ERROR closing ring buffer reader: %v", err)
			errs = append(errs, fmt.Errorf("failed to close ring buffer reader: %w", err))
		} else {
			c.debugLog("Ring buffer reader closed successfully")
		}
	}

	if c.link != nil {
		c.debugLog("Detaching kprobe...")
		if err := c.link.Close(); err != nil {
			c.debugLog("ERROR detaching kprobe: %v", err)
			errs = append(errs, fmt.Errorf("failed to close link: %w", err))
		} else {
			c.debugLog("Kprobe detached successfully")
		}
	}

	if c.objs != nil {
		c.debugLog("Closing eBPF objects (programs and maps)...")
		if err := c.objs.Close(); err != nil {
			c.debugLog("ERROR closing eBPF objects: %v", err)
			errs = append(errs, fmt.Errorf("failed to close eBPF objects: %w", err))
		} else {
			c.debugLog("eBPF objects closed successfully")
		}
	}

	if len(errs) > 0 {
		c.debugLog("Cleanup completed with %d error(s)", len(errs))
		return fmt.Errorf("cleanup errors: %v", errs)
	}
	c.debugLog("Cleanup completed successfully")
	return nil
}

// getKernelSymbolAddr reads /proc/kallsyms to find a kernel symbol's address
func getKernelSymbolAddr(symbol string) (uint64, error) {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return 0, fmt.Errorf("failed to open /proc/kallsyms: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		// Format: address type name [module]
		addr := fields[0]
		name := fields[2]

		if name == symbol {
			// Parse hex address
			address, err := strconv.ParseUint(addr, 16, 64)
			if err != nil {
				return 0, fmt.Errorf("failed to parse address %s: %w", addr, err)
			}
			return address, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("error reading /proc/kallsyms: %w", err)
	}

	return 0, fmt.Errorf("symbol %s not found in /proc/kallsyms", symbol)
}
