package checks

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// HiddenFileCheck detects files that can be accessed but are hidden from directory listings
// This is a common rootkit technique where getdents64 is hooked to hide files
// We monitor execve, openat, open, and openat2 syscalls to detect hidden files
type HiddenFileCheck struct {
	objs            *bpfObjects
	links           []link.Link
	reader          *ringbuf.Reader
	done            chan struct{}
	debug           bool
	monitorDuration time.Duration
}

// debugLog prints a message only if debug mode is enabled
func (c *HiddenFileCheck) debugLog(format string, args ...interface{}) {
	if c.debug {
		timestamp := time.Now().Format("15:04:05.000")
		msg := fmt.Sprintf(format, args...)
		log.Printf("[HIDDEN-FILES %s] %s", timestamp, msg)
	}
}

// fileAccessEvent matches the C structure in the eBPF program
type fileAccessEvent struct {
	PID         uint32
	SyscallType uint32 // 0=execve, 1=openat, 2=open, 3=openat2
	Filename    [256]byte
}

// NewHiddenFileCheck creates a new hidden file detection check
func NewHiddenFileCheck() *HiddenFileCheck {
	return &HiddenFileCheck{
		done:            make(chan struct{}),
		monitorDuration: 5 * time.Second, // Default 5 seconds
	}
}

// SetDebug enables or disables debug mode
func (c *HiddenFileCheck) SetDebug(debug bool) {
	c.debug = debug
}

// SetMonitorDuration sets the monitoring duration for the check
func (c *HiddenFileCheck) SetMonitorDuration(duration time.Duration) {
	c.monitorDuration = duration
}

// Name returns the check name
func (c *HiddenFileCheck) Name() string {
	return "Hidden File Detection"
}

// Description returns what this check does
func (c *HiddenFileCheck) Description() string {
	return "Detects files that are hidden from directory listings by monitoring execve, openat, open, and openat2 syscalls on PATH directories"
}

// Run executes the hidden file detection check
func (c *HiddenFileCheck) Run() (Result, error) {
	start := time.Now()
	result := Result{
		Cell:       "hidden_file",
		Status:     StatusOK,
		Suspicious: make([]Finding, 0),
	}

	c.debugLog("Starting hidden files detection check")
	c.debugLog("Step 1: Loading eBPF objects with CO-RE...")

	// Load the eBPF spec first to allow constant rewriting
	spec, err := loadBpf()
	if err != nil {
		c.debugLog("ERROR: Failed to load eBPF spec: %v", err)
		result.Status = StatusError
		result.SetError(fmt.Errorf("failed to load eBPF spec: %w", err))
		result.SetDuration(time.Since(start))
		return result, err
	}

	// Get PATH directories from environment
	pathDirs := getPathDirectories()
	c.debugLog("Configuring BPF program to monitor %d PATH directories", len(pathDirs))

	// Build path prefixes with trailing slashes for prefix matching
	pathPrefixes := make([]string, 0, len(pathDirs))
	for _, dir := range pathDirs {
		if !strings.HasSuffix(dir, "/") {
			dir = dir + "/"
		}
		pathPrefixes = append(pathPrefixes, dir)
		c.debugLog("  - Will monitor: %s", dir)
	}

	// Configure monitored paths via .rodata constants
	if len(pathPrefixes) > 0 && len(pathPrefixes) <= 8 {
		// Build the configuration struct matching the BPF-side layout
		// IMPORTANT: Must match struct cfg_paths in zygarde.bpf.c exactly
		type cfgPaths struct {
			UseCustomPaths bool         // 1 byte
			_              [3]byte      // 3 bytes padding
			PrefixCount    uint32       // 4 bytes
			PrefixLens     [8]uint16    // 16 bytes
			Prefixes       [8][256]byte // 2048 bytes
		}

		cfg := cfgPaths{
			UseCustomPaths: true,
			PrefixCount:    uint32(len(pathPrefixes)),
		}

		for i, prefix := range pathPrefixes {
			if i >= 8 {
				break
			}
			cfg.PrefixLens[i] = uint16(len(prefix))
			copy(cfg.Prefixes[i][:], prefix)
		}

		// Try to rewrite the .rodata section
		err = spec.RewriteConstants(map[string]interface{}{
			"zygarde_cfg": cfg,
		})
		if err != nil {
			c.debugLog("WARNING: Failed to rewrite .rodata constants: %v (falling back to built-in defaults)", err)
		} else {
			c.debugLog("SUCCESS: Configured %d custom PATH prefixes in .rodata", len(pathPrefixes))
		}
	} else if len(pathPrefixes) > 8 {
		c.debugLog("WARNING: PATH has %d directories but only 8 can be configured, using first 8", len(pathPrefixes))
	} // Load the eBPF program with the modified spec
	objs := &bpfObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		c.debugLog("ERROR: Failed to load eBPF objects: %v", err)
		result.Status = StatusError
		result.SetError(fmt.Errorf("failed to load eBPF objects: %w", err))
		result.SetDuration(time.Since(start))
		return result, err
	}
	c.objs = objs
	c.debugLog("SUCCESS: eBPF objects loaded successfully")
	c.debugLog("  - CO-RE relocations applied")
	c.debugLog("  - BPF programs verified and loaded into kernel")
	c.debugLog("  - BPF maps created (execve_events ring buffer)")
	c.debugLog("  - Monitoring %d PATH directories from $PATH environment", len(pathPrefixes))

	c.debugLog("Step 2: Attaching to syscall tracepoints...")

	// Attach to multiple syscall tracepoints
	syscalls := []struct {
		group string
		name  string
		prog  *ebpf.Program
	}{
		{"syscalls", "sys_enter_execve", objs.TraceExecve},
		{"syscalls", "sys_enter_openat", objs.TraceOpenat},
		{"syscalls", "sys_enter_open", objs.TraceOpen},
		{"syscalls", "sys_enter_openat2", objs.TraceOpenat2},
	}

	c.links = make([]link.Link, 0, len(syscalls))
	attachedCount := 0

	for _, sc := range syscalls {
		c.debugLog("Attaching to tracepoint: %s/%s...", sc.group, sc.name)
		tp, err := link.Tracepoint(sc.group, sc.name, sc.prog, nil)
		if err != nil {
			// openat2 might not be available on older kernels, so we don't fail
			if sc.name == "sys_enter_openat2" {
				c.debugLog("WARNING: Could not attach to %s (might not be available on this kernel): %v", sc.name, err)
				continue
			}
			c.debugLog("ERROR: Failed to attach tracepoint %s: %v", sc.name, err)
			result.Status = StatusError
			result.SetError(fmt.Errorf("failed to attach tracepoint %s: %w", sc.name, err))
			result.SetDuration(time.Since(start))
			return result, err
		}
		c.links = append(c.links, tp)
		attachedCount++
		c.debugLog("SUCCESS: Attached to %s/%s", sc.group, sc.name)
	}

	c.debugLog("Successfully attached to %d/%d tracepoints", attachedCount, len(syscalls))

	c.debugLog("Step 3: Opening ring buffer to receive events...")

	// Open the ring buffer to receive events
	rd, err := ringbuf.NewReader(objs.ExecveEvents)
	if err != nil {
		c.debugLog("ERROR: Failed to open ring buffer: %v", err)
		result.Status = StatusError
		result.SetError(fmt.Errorf("failed to open ring buffer: %w", err))
		result.SetDuration(time.Since(start))
		return result, err
	}
	c.reader = rd
	c.debugLog("SUCCESS: Ring buffer reader created")

	// Monitor for a period of time
	timeout := time.After(c.monitorDuration)

	hiddenFiles := make(map[string]bool)
	eventCount := 0
	syscallCounts := make(map[string]int) // Track events per syscall type

	c.debugLog("Step 4: Starting monitoring phase for %v...", c.monitorDuration)
	pathDirsStr := strings.Join(pathDirs, ", ")
	if len(pathDirsStr) > 100 {
		pathDirsStr = pathDirsStr[:100] + "..."
	}
	c.debugLog("Monitoring file access in PATH directories: %s", pathDirsStr)

	// Read events from the ring buffer
	go func() {
		for {
			select {
			case <-c.done:
				c.debugLog("Event reader goroutine shutting down")
				return
			default:
				record, err := rd.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						c.debugLog("Ring buffer closed, stopping event reader")
						return
					}
					c.debugLog("Error reading from ring buffer: %v", err)
					continue
				}

				// Parse the event
				var event fileAccessEvent
				if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
					c.debugLog("Failed to parse event: %v", err)
					continue
				}

				// Extract the filename (null-terminated string)
				filename := string(bytes.TrimRight(event.Filename[:], "\x00"))
				if filename == "" {
					continue
				}

				eventCount++

				// Track syscall type
				syscallName := getSyscallName(event.SyscallType)
				syscallCounts[syscallName]++

				if eventCount <= 10 || c.debug {
					c.debugLog("Event #%d: PID=%d, syscall=%s, file=%s", eventCount, event.PID, syscallName, filename)
				}

				// Check if the file exists from user-space perspective
				statInfo, statErr := os.Stat(filename)

				// Extract directory and base filename
				dir := "/"
				baseName := filename
				lastSlash := strings.LastIndex(filename, "/")
				if lastSlash >= 0 {
					dir = filename[:lastSlash]
					if dir == "" {
						dir = "/"
					}
					baseName = filename[lastSlash+1:]
				}

				// Check if file appears in directory listing
				foundInListing := false
				if baseName != "" {
					entries, listErr := os.ReadDir(dir)
					if listErr == nil {
						for _, entry := range entries {
							if entry.Name() == baseName {
								foundInListing = true
								break
							}
						}
					}
				}

				// Determine file status based on stat and listing results
				statExists := statErr == nil && statInfo != nil

				if statExists && !foundInListing {
					// File exists via stat but NOT in directory listing - HIDDEN FILE!
					if !hiddenFiles[filename] {
						hiddenFiles[filename] = true
						c.debugLog("**ALERT** Hidden file detected: %s (accessible via stat but hidden from directory listing)", filename)
						result.Status = StatusSuspicious
						result.Suspicious = append(result.Suspicious, Finding{
							Description: fmt.Sprintf("File '%s' is accessible but hidden from directory listings - possible rootkit", filename),
							Details: map[string]string{
								"file_path":      filename,
								"pid":            fmt.Sprintf("%d", event.PID),
								"syscall":        syscallName,
								"detection_type": "hidden_file",
								"stat_result":    "exists",
								"listing_result": "not_found",
							},
						})
					}
				} else if !statExists && !foundInListing {
					// Neither stat nor listing found it - likely just a non-existent file
					c.debugLog("File not found (likely non-existent): %s", filename)
				} else if statExists && foundInListing {
					// Both stat and listing found it - normal file
					c.debugLog("Normal file: %s", filename)
				}
			}
		}
	}()

	// Wait for monitoring period
	<-timeout
	c.debugLog("Monitoring period completed, stopping event collection...")
	close(c.done)

	// Give a moment for any pending events to be processed
	time.Sleep(100 * time.Millisecond)

	c.debugLog("Step 5: Analysis complete")
	c.debugLog("Total events received: %d", eventCount)
	c.debugLog("Events by syscall type: %v", syscallCounts)
	c.debugLog("Hidden files detected: %d", len(hiddenFiles))

	// Set result message with syscall breakdown
	if len(hiddenFiles) > 0 {
		result.Message = fmt.Sprintf("Found %d hidden file(s) (monitored %d events: %v)",
			len(hiddenFiles), eventCount, syscallCounts)
	} else {
		result.Message = fmt.Sprintf("No hidden files detected (monitored %d events: %v)",
			eventCount, syscallCounts)
	}

	result.SetDuration(time.Since(start))
	return result, nil
}

// Cleanup closes the eBPF resources
func (c *HiddenFileCheck) Cleanup() error {
	c.debugLog("Starting cleanup...")
	var errs []error

	// Signal goroutine to stop
	select {
	case <-c.done:
		c.debugLog("Done channel already closed")
		// Already closed
	default:
		c.debugLog("Closing done channel to stop goroutine")
		close(c.done)
	}

	if c.reader != nil {
		c.debugLog("Closing ring buffer reader...")
		if err := c.reader.Close(); err != nil {
			c.debugLog("ERROR closing ring buffer reader: %v", err)
			errs = append(errs, fmt.Errorf("failed to close ring buffer reader: %w", err))
		} else {
			c.debugLog("Ring buffer reader closed successfully")
		}
	}

	// Close all links
	c.debugLog("Detaching %d tracepoint(s)...", len(c.links))
	for i, lnk := range c.links {
		if lnk != nil {
			c.debugLog("Detaching tracepoint %d/%d...", i+1, len(c.links))
			if err := lnk.Close(); err != nil {
				c.debugLog("ERROR detaching tracepoint %d: %v", i, err)
				errs = append(errs, fmt.Errorf("failed to close link %d: %w", i, err))
			} else {
				c.debugLog("Tracepoint %d detached successfully", i+1)
			}
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

// getSyscallName returns the syscall name from the type
func getSyscallName(syscallType uint32) string {
	switch syscallType {
	case 0:
		return "execve"
	case 1:
		return "openat"
	case 2:
		return "open"
	case 3:
		return "openat2"
	default:
		return "unknown"
	}
}

// getPathDirectories returns a list of directories from the PATH environment variable
func getPathDirectories() []string {
	pathEnv := os.Getenv("PATH")

	// Always include common library and temp directories in addition to PATH
	commonDirs := []string{"/tmp", "/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/local/lib"}

	if pathEnv == "" {
		// Default PATH
		defaultPath := []string{"/bin", "/usr/bin", "/sbin", "/usr/sbin", "/usr/local/bin"}
		return append(defaultPath, commonDirs...)
	}

	dirs := strings.Split(pathEnv, ":")
	result := make([]string, 0, len(dirs)+len(commonDirs))
	for _, dir := range dirs {
		dir = strings.TrimSpace(dir)
		if dir != "" {
			result = append(result, dir)
		}
	}
	// Add common directories that might not be in PATH
	result = append(result, commonDirs...)
	return result
}
