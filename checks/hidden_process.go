package checks

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
)

// HiddenProcessCheck detects hidden processes by comparing
// kernel-level process enumeration (via BPF iterator) with
// userspace process listing (via /proc)
type HiddenProcessCheck struct {
	objs  *bpfObjects
	iter  link.Link
	debug bool
}

// taskInfo matches the C structure in the eBPF program
type taskInfo struct {
	Pid   uint32
	Tid   uint32
	Ppid  uint32
	State uint32
	Comm  [16]byte
}

// ProcessInfo represents a process/thread from the kernel
type ProcessInfo struct {
	PID   uint32
	TID   uint32
	PPID  uint32
	State uint32
	Comm  string
}

// NewHiddenProcessCheck creates a new hidden process detection check
func NewHiddenProcessCheck() *HiddenProcessCheck {
	return &HiddenProcessCheck{}
}

// SetDebug enables or disables debug mode
func (c *HiddenProcessCheck) SetDebug(debug bool) {
	c.debug = debug
}

// debugLog prints a message only if debug mode is enabled
func (c *HiddenProcessCheck) debugLog(format string, args ...interface{}) {
	if c.debug {
		timestamp := time.Now().Format("15:04:05.000")
		msg := fmt.Sprintf(format, args...)
		log.Printf("[HIDDEN-PROC %s] %s", timestamp, msg)
	}
}

// Name returns the check name
func (c *HiddenProcessCheck) Name() string {
	return "Hidden Process Detection"
}

// Description returns what this check does
func (c *HiddenProcessCheck) Description() string {
	return "Detects hidden processes/threads by comparing kernel task list (BPF iterator) with userspace /proc enumeration"
}

// Run executes the hidden process detection check
func (c *HiddenProcessCheck) Run() (Result, error) {
	start := time.Now()
	result := Result{
		Status:   StatusOK,
		Findings: make([]Finding, 0),
	}

	c.debugLog("Starting hidden process detection")
	c.debugLog("Step 1: Loading eBPF objects...")

	// Load the eBPF spec and objects (no .rodata rewriting needed for process check)
	spec, err := loadBpf()
	if err != nil {
		c.debugLog("ERROR: Failed to load eBPF spec: %v", err)
		result.Status = StatusError
		result.Error = fmt.Errorf("failed to load eBPF spec: %w", err)
		result.Duration = time.Since(start)
		return result, err
	}

	// Load the eBPF program
	objs := &bpfObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		c.debugLog("ERROR: Failed to load eBPF objects: %v", err)
		result.Status = StatusError
		result.Error = fmt.Errorf("failed to load eBPF objects: %w", err)
		result.Duration = time.Since(start)
		return result, err
	}
	c.objs = objs
	c.debugLog("SUCCESS: eBPF objects loaded")

	c.debugLog("Step 2: Creating BPF iterator link...")

	// Create iterator link for task enumeration
	iter, err := link.AttachIter(link.IterOptions{
		Program: objs.DumpTask,
	})
	if err != nil {
		c.debugLog("ERROR: Failed to attach iterator: %v", err)
		result.Status = StatusError
		result.Error = fmt.Errorf("failed to attach BPF iterator: %w", err)
		result.Duration = time.Since(start)
		return result, err
	}
	c.iter = iter
	c.debugLog("SUCCESS: BPF iterator attached")

	c.debugLog("Step 3: Opening BPF iterator to read tasks...")

	iterFile, err := iter.Open()
	if err != nil {
		c.debugLog("ERROR: Failed to open BPF iterator: %v", err)
		result.Status = StatusError
		result.Error = fmt.Errorf("failed to open BPF iterator: %w", err)
		result.Duration = time.Since(start)
		return result, err
	}
	defer iterFile.Close()

	c.debugLog("Step 4: Reading and parsing tasks from BPF iterator...")

	kernelTasks := make(map[uint32]*ProcessInfo)
	var allData bytes.Buffer
	readBuf := make([]byte, 8192)

	for {
		n, err := iterFile.Read(readBuf)
		c.debugLog("Iterator read: %d bytes (err=%v)", n, err)
		if n > 0 {
			allData.Write(readBuf[:n])
		}
		// The iterator returns EOF when done.
		if err != nil {
			break
		}
	}

	c.debugLog("Step 5: Parsing collected kernel task data (%d bytes)...", allData.Len())

	reader := bytes.NewReader(allData.Bytes())
	var task taskInfo

	for {
		err := binary.Read(reader, binary.LittleEndian, &task)
		if err != nil {
			// When the reader is exhausted, binary.Read returns io.EOF
			break
		}

		commStr := string(bytes.TrimRight(task.Comm[:], "\x00"))
		proc := &ProcessInfo{
			PID:   task.Pid,
			TID:   task.Tid,
			PPID:  task.Ppid,
			State: task.State,
			Comm:  commStr,
		}

		if _, exists := kernelTasks[proc.PID]; !exists {
			kernelTasks[proc.PID] = proc
		}
	}

	c.debugLog("Collected %d processes from kernel", len(kernelTasks))

	c.debugLog("Step 6: Enumerating processes from /proc...")

	// Get userspace process list from /proc
	procPids, err := c.getProcPids()
	if err != nil {
		c.debugLog("ERROR: Failed to enumerate /proc: %v", err)
		result.Status = StatusError
		result.Error = fmt.Errorf("failed to enumerate /proc: %w", err)
		result.Duration = time.Since(start)
		return result, err
	}
	c.debugLog("Found %d processes in /proc", len(procPids))

	c.debugLog("Step 7: Comparing kernel tasks with /proc...")

	// Compare: Find processes in kernel but not in /proc (hidden from userspace)
	var hiddenCount int
	for pid, proc := range kernelTasks {
		if pid == 0 {
			continue // Skip kernel idle process
		}

		if !procPids[pid] {
			hiddenCount++
			c.debugLog("SUSPICIOUS: PID %d (%s) found in kernel but NOT in /proc", pid, proc.Comm)
			result.Findings = append(result.Findings, Finding{
				Description: fmt.Sprintf("Process hidden from userspace: PID %d (%s)", pid, proc.Comm),
				Details: map[string]string{
					"pid":         fmt.Sprintf("%d", pid),
					"comm":        proc.Comm,
					"ppid":        fmt.Sprintf("%d", proc.PPID),
					"state":       fmt.Sprintf("%d", proc.State),
					"detected_by": "BPF iterator",
					"hidden_from": "/proc filesystem",
				},
			})
		}
	}

	// Also check reverse: processes in /proc but not in kernel (less likely but possible)
	var orphanedCount int
	for pid := range procPids {
		if _, exists := kernelTasks[pid]; !exists {
			orphanedCount++
			c.debugLog("WARNING: PID %d in /proc but NOT found in kernel enumeration", pid)
			// This is less critical - might be timing issue or iterator limitation
		}
	}

	c.debugLog("Comparison complete: %d hidden from /proc, %d only in /proc", hiddenCount, orphanedCount)

	// Set result status
	if hiddenCount > 0 {
		result.Status = StatusSuspicious
		result.Message = fmt.Sprintf("Found %d process(es) hidden from userspace", hiddenCount)
		c.debugLog("RESULT: SUSPICIOUS - %d hidden processes detected", hiddenCount)
	} else {
		result.Status = StatusOK
		result.Message = fmt.Sprintf("No hidden processes detected (%d kernel tasks, %d /proc entries)",
			len(kernelTasks), len(procPids))
		c.debugLog("RESULT: OK - No hidden processes detected")
	}

	result.Duration = time.Since(start)
	return result, nil
}

// getProcPids returns a map of PIDs found in /proc
func (c *HiddenProcessCheck) getProcPids() (map[uint32]bool, error) {
	pids := make(map[uint32]bool)

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check if directory name is a number (PID)
		name := entry.Name()
		if pid, err := strconv.ParseUint(name, 10, 32); err == nil {
			// Verify it's a valid process directory by checking for /proc/PID/stat
			statPath := filepath.Join("/proc", name, "stat")
			if _, err := os.Stat(statPath); err == nil {
				pids[uint32(pid)] = true
			}
		}
	}

	return pids, nil
}

// Cleanup releases resources
func (c *HiddenProcessCheck) Cleanup() error {
	c.debugLog("Cleaning up hidden process check resources...")

	var errs []error

	if c.iter != nil {
		if err := c.iter.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close iterator link: %w", err))
		}
		c.iter = nil
	}

	if c.objs != nil {
		if err := c.objs.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close eBPF objects: %w", err))
		}
		c.objs = nil
	}

	if len(errs) > 0 {
		errStrs := make([]string, len(errs))
		for i, err := range errs {
			errStrs[i] = err.Error()
		}
		return fmt.Errorf("cleanup errors: %s", strings.Join(errStrs, "; "))
	}

	c.debugLog("Cleanup complete")
	return nil
}
