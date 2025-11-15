package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"zygarde/checks"
)

// ANSI color codes
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
)

const banner = `
 ███████╗██╗   ██╗ ██████╗  █████╗ ██████╗ ██████╗ ███████╗
 ╚══███╔╝╚██╗ ██╔╝██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██╔════╝
   ███╔╝  ╚████╔╝ ██║  ███╗███████║██████╔╝██║  ██║█████╗  
  ███╔╝    ╚██╔╝  ██║   ██║██╔══██║██╔══██╗██║  ██║██╔══╝  
 ███████╗   ██║   ╚██████╔╝██║  ██║██║  ██║██████╔╝███████╗
 ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝
                                                             
 Guardian of the Kernel - eBPF Rootkit Detection
 Version 0.0.1 - 10% Form`

// Global debug flag
var debugMode bool

// DebugLog prints a message only if debug mode is enabled
func DebugLog(format string, args ...any) {
	if debugMode {
		timestamp := time.Now().Format("15:04:05.000")
		msg := fmt.Sprintf(format, args...)
		log.Printf("[DEBUG %s] %s", timestamp, msg)
	}
}

func main() {
	// Parse command-line flags
	debugFlag := flag.Bool("d", false, "Enable debug mode with verbose output")
	debugFlagLong := flag.Bool("debug", false, "Enable debug mode with verbose output")
	flag.Parse()

	// Set global debug mode
	debugMode = *debugFlag || *debugFlagLong

	// Configure logging
	log.SetFlags(0) // Remove default timestamp since we add our own
	if debugMode {
		log.SetOutput(os.Stdout)
		fmt.Println("[DEBUG MODE ENABLED - Verbose output active]")
		fmt.Println()
	} else {
		log.SetOutput(os.Stderr)
	}

	fmt.Println(banner)

	DebugLog("Starting Zygarde Core with debug mode enabled")
	DebugLog("OS: %s, Kernel: %s", os.Getenv("OSTYPE"), getKernelVersion())
	DebugLog("UID: %d, EUID: %d", os.Getuid(), os.Geteuid())

	// Check if running as root
	if os.Geteuid() != 0 {
		fmt.Printf("%s[-]%s Error: This tool must be run as root (for eBPF operations)\n", ColorRed, ColorReset)
		fmt.Println("    Please run with: sudo ./zygarde")
		os.Exit(1)
	}

	// Activate Zygarde Cells
	DebugLog("Activating Zygarde Cells...")
	allCells := []checks.Check{
		checks.NewSyscallCheck(),
		checks.NewModulesCheck(),
		checks.NewHiddenFilesCheck(),
		checks.NewHiddenProcessesCheck(),
	}
	DebugLog("Activated %d Cells", len(allCells))

	// Set debug mode on all cells that support it
	for _, cell := range allCells {
		if debuggable, ok := cell.(checks.Debuggable); ok {
			debuggable.SetDebug(debugMode)
			DebugLog("Enabled debug mode for Cell: %s", cell.Name())
		}
	}

	fmt.Printf("Deploying %d Zygarde Cells for system analysis...\n\n", len(allCells))

	// Execute all Cells
	var suspiciousCount, errorCount, okCount int
	allResults := make([]struct {
		cell   checks.Check
		result checks.Result
	}, 0)

	for i, cell := range allCells {
		fmt.Printf("[Cell %d/%d] Executing: %s\n", i+1, len(allCells), cell.Name())
		fmt.Printf("            %s\n", cell.Description())

		DebugLog(strings.Repeat("=", 60))
		DebugLog("Activating Cell [%d/%d]: %s", i+1, len(allCells), cell.Name())
		DebugLog("Description: %s", cell.Description())
		cellStart := time.Now()

		result, err := cell.Run()

		DebugLog("Cell completed in %.3fs", time.Since(cellStart).Seconds())
		allResults = append(allResults, struct {
			cell   checks.Check
			result checks.Result
		}{cell: cell, result: result})

		// Print immediate result
		statusSymbol, statusColor := getStatusSymbol(result.Status)
		fmt.Printf("            %s%s%s %s (%.2fs)\n", statusColor, statusSymbol, ColorReset, result.Message, result.Duration.Seconds())

		// Show findings immediately
		if len(result.Findings) > 0 {
			for _, finding := range result.Findings {
				fmt.Printf("              %s[*]%s %s\n", ColorYellow, ColorReset, finding.Description)
				if len(finding.Details) > 0 {
					for key, value := range finding.Details {
						fmt.Printf("                  - %s: %s\n", key, value)
					}
				}
			}
		}

		if err != nil {
			fmt.Printf("            %s[*]%s Error: %v\n", ColorRed, ColorReset, err)
		}

		fmt.Println()

		// Update counters
		switch result.Status {
		case checks.StatusOK:
			okCount++
		case checks.StatusSuspicious:
			suspiciousCount++
		case checks.StatusError:
			errorCount++
		}
	}

	// Print summary report
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("ZYGARDE CORE ANALYSIS - SUMMARY REPORT")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Total Cells Deployed: %d\n", len(allCells))
	fmt.Printf("  %s[+]%s OK:         %d\n", ColorGreen, ColorReset, okCount)
	fmt.Printf("  %s[*]%s SUSPICIOUS: %d\n", ColorYellow, ColorReset, suspiciousCount)
	fmt.Printf("  %s[-]%s ERROR:      %d\n", ColorRed, ColorReset, errorCount)
	fmt.Println()

	// Print detailed findings if any
	totalFindings := 0
	for _, ar := range allResults {
		totalFindings += len(ar.result.Findings)
	}

	if totalFindings > 0 {
		fmt.Println("DETAILED FINDINGS FROM CELLS:")
		fmt.Println(strings.Repeat("-", 70))
		for _, ar := range allResults {
			if len(ar.result.Findings) > 0 {
				fmt.Printf("\n%s Cell:\n", ar.cell.Name())
				for i, finding := range ar.result.Findings {
					fmt.Printf("  [%d] %s\n", i+1, finding.Description)
					if len(finding.Details) > 0 {
						for key, value := range finding.Details {
							fmt.Printf("      • %s: %s\n", key, value)
						}
					}
				}
			}
		}
		fmt.Println()
	}

	// Deactivate all Cells
	DebugLog("Deactivating Zygarde Cells...")
	fmt.Println("Deactivating Cells...")
	for _, cell := range allCells {
		DebugLog("Deactivating Cell: %s", cell.Name())
		if err := cell.Cleanup(); err != nil {
			fmt.Printf("  Warning: Failed to deactivate %s Cell: %v\n", cell.Name(), err)
			DebugLog("Deactivation error for %s: %v", cell.Name(), err)
		} else {
			DebugLog("Successfully deactivated: %s Cell", cell.Name())
		}
	}
	DebugLog("Cell deactivation completed")

	// Exit with appropriate code
	if suspiciousCount > 0 {
		fmt.Println(strings.Repeat("=", 70))
		fmt.Printf("%s[*] ECOSYSTEM THREAT DETECTED!%s\n", ColorRed, ColorReset)
		fmt.Println(strings.Repeat("=", 70))
		os.Exit(2)
	} else if errorCount > 0 {
		fmt.Println(strings.Repeat("=", 70))
		fmt.Printf("%s[*] WARNING: Some Cells failed to complete analysis%s\n", ColorYellow, ColorReset)
		fmt.Println(strings.Repeat("=", 70))
		os.Exit(1)
	} else {
		fmt.Println(strings.Repeat("=", 70))
		fmt.Printf("%s[+] Ecosystem stable - no threats detected%s\n", ColorGreen, ColorReset)
		fmt.Println(strings.Repeat("=", 70))
		os.Exit(0)
	}
}

// getStatusSymbol returns a symbol and color for the status
func getStatusSymbol(status checks.Status) (string, string) {
	switch status {
	case checks.StatusOK:
		return "[+]", ColorGreen
	case checks.StatusSuspicious:
		return "[*]", ColorYellow
	case checks.StatusError:
		return "[-]", ColorRed
	default:
		return "[?]", ColorReset
	}
}

// getKernelVersion returns the kernel version string
func getKernelVersion() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}
