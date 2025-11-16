package checks

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

// HiddenKernelModuleCheck detects kernel modules that are hidden from user-space
// by comparing /proc/modules with /sys/module
// Note: This Cell is actually a scam that does not use ebpf at all, but
// there's currently no module ebpf iterators in default kernels
type HiddenKernelModuleCheck struct {
	debug bool
}

// debugLog prints a message only if debug mode is enabled
func (c *HiddenKernelModuleCheck) debugLog(format string, args ...interface{}) {
	if c.debug {
		timestamp := time.Now().Format("15:04:05.000")
		msg := fmt.Sprintf(format, args...)
		log.Printf("[MODULES-CHECK %s] %s", timestamp, msg)
	}
}

// NewHiddenKernelModuleCheck creates a new hidden module check
func NewHiddenKernelModuleCheck() *HiddenKernelModuleCheck {
	return &HiddenKernelModuleCheck{}
}

// SetDebug enables or disables debug mode
func (c *HiddenKernelModuleCheck) SetDebug(debug bool) {
	c.debug = debug
}

// Name returns the check name
func (c *HiddenKernelModuleCheck) Name() string {
	return "Hidden Kernel Module Detection"
}

// Description returns what this check does
func (c *HiddenKernelModuleCheck) Description() string {
	return "Detects kernel modules hidden from lsmod by comparing /proc/modules with /sys/module"
}

// Run executes the hidden module detection check
func (c *HiddenKernelModuleCheck) Run() (Result, error) {
	start := time.Now()
	result := Result{
		Status:   StatusOK,
		Findings: make([]Finding, 0),
	}

	c.debugLog("Starting hidden kernel modules check")
	c.debugLog("Step 1: Reading /proc/modules...")

	// Read modules from /proc/modules (what the kernel reports)
	procModules, err := readProcModules()
	if err != nil {
		c.debugLog("ERROR: Failed to read /proc/modules: %v", err)
		result.Status = StatusError
		result.Error = fmt.Errorf("failed to read /proc/modules: %w", err)
		result.Duration = time.Since(start)
		return result, err
	}
	c.debugLog("Found %d modules in /proc/modules", len(procModules))
	if c.debug {
		moduleNames := make([]string, 0, len(procModules))
		for name := range procModules {
			moduleNames = append(moduleNames, name)
		}
		if len(moduleNames) <= 20 {
			c.debugLog("Modules: %v", moduleNames)
		} else {
			c.debugLog("First 20 modules: %v...", moduleNames[:20])
		}
	}

	c.debugLog("Step 2: Reading /sys/module directory...")

	// Read the visible modules from /sys/module
	visibleModules, err := c.readVisibleModules()
	if err != nil {
		c.debugLog("ERROR: Failed to read visible modules: %v", err)
		result.Status = StatusError
		result.Error = fmt.Errorf("failed to read visible modules: %w", err)
		result.Duration = time.Since(start)
		return result, err
	}
	c.debugLog("Found %d modules in /sys/module", len(visibleModules))
	if c.debug {
		moduleNames := make([]string, 0, len(visibleModules))
		for name := range visibleModules {
			moduleNames = append(moduleNames, name)
		}
		if len(moduleNames) <= 20 {
			c.debugLog("Visible modules: %v", moduleNames)
		} else {
			c.debugLog("First 20 visible modules: %v...", moduleNames[:20])
		}
	}

	c.debugLog("Step 3: Comparing /proc/modules with /sys/module...")

	// Compare the two lists to find hidden modules
	// Modules in /proc/modules but not in /sys/module are suspicious
	hiddenModules := c.findHiddenModules(procModules, visibleModules)

	if len(hiddenModules) > 0 {
		c.debugLog("**ALERT** Found %d hidden module(s)!", len(hiddenModules))
		for _, modName := range hiddenModules {
			c.debugLog("  - Hidden module: %s", modName)
		}
		result.Status = StatusSuspicious
		for _, modName := range hiddenModules {
			result.Findings = append(result.Findings, Finding{
				Description: fmt.Sprintf("Module '%s' is in /proc/modules but hidden from /sys/module", modName),
				Details: map[string]string{
					"module_name":    modName,
					"detection_type": "hidden_from_sysfs",
				},
			})
		}
		result.Message = fmt.Sprintf("Found %d hidden kernel module(s)", len(hiddenModules))
	} else {
		c.debugLog("SUCCESS: All %d kernel modules are visible", len(procModules))
		result.Message = fmt.Sprintf("All %d kernel modules are visible", len(procModules))
	}

	result.Duration = time.Since(start)
	return result, nil
}

// readVisibleModules reads the list of modules visible in /sys/module
func (c *HiddenKernelModuleCheck) readVisibleModules() (map[string]bool, error) {
	modules := make(map[string]bool)

	c.debugLog("Opening /sys/module directory...")
	entries, err := os.ReadDir("/sys/module")
	if err != nil {
		return nil, fmt.Errorf("failed to read /sys/module: %w", err)
	}

	c.debugLog("Processing %d entries from /sys/module", len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			modules[entry.Name()] = true
		}
	}
	c.debugLog("Found %d module directories in /sys/module", len(modules))

	return modules, nil
}

// findHiddenModules compares proc modules with visible modules
func (c *HiddenKernelModuleCheck) findHiddenModules(procModules, visibleModules map[string]bool) []string {
	hidden := make([]string, 0)

	c.debugLog("Comparing %d /proc/modules entries against %d /sys/module entries", len(procModules), len(visibleModules))

	for modName := range procModules {
		// Skip empty names
		if modName == "" {
			continue
		}

		// Check if this proc module is visible in sysfs
		if !visibleModules[modName] {
			c.debugLog("Hidden module detected: %s (in /proc/modules but not in /sys/module)", modName)
			hidden = append(hidden, modName)
		}
	}

	return hidden
}

// Cleanup closes any resources (none needed in simplified version)
func (c *HiddenKernelModuleCheck) Cleanup() error {
	c.debugLog("Cleanup: No resources to clean up for modules check")
	return nil
}

// readProcModules reads the module list from /proc/modules
func readProcModules() (map[string]bool, error) {
	modules := make(map[string]bool)

	file, err := os.Open("/proc/modules")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc/modules: %w", err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("error reading /proc/modules: %w", err)
		}

		// Format: module_name size used_by_count used_by_list state address
		fields := strings.Fields(line)
		if len(fields) > 0 {
			modules[fields[0]] = true
		}
	}

	return modules, nil
}
