package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"gohunt/checks"
)

const banner = `
  ██████╗  ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗
 ██╔════╝ ██╔═══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝
 ██║  ███╗██║   ██║███████║██║   ██║██╔██╗ ██║   ██║   
 ██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   
 ╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   
  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   
                                                        
 eBPF-based Rootkit Detection Tool
 Version 1.0.0
`

// Global debug flag
var debugMode bool

// DebugLog prints a message only if debug mode is enabled
func DebugLog(format string, args ...interface{}) {
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

	DebugLog("Starting GoHunt with debug mode enabled")
	DebugLog("OS: %s, Kernel: %s", os.Getenv("OSTYPE"), getKernelVersion())
	DebugLog("UID: %d, EUID: %d", os.Getuid(), os.Geteuid())

	// Check if running as root
	if os.Geteuid() != 0 {
		fmt.Println("❌ Error: This tool must be run as root (for eBPF operations)")
		fmt.Println("   Please run with: sudo ./gohunt")
		os.Exit(1)
	}

	// Register all checks
	DebugLog("Registering checks...")
	allChecks := []checks.Check{
		checks.NewSyscallCheck(),
		checks.NewModulesCheck(),
		checks.NewHiddenFilesCheck(),
	}
	DebugLog("Registered %d checks", len(allChecks))

	// Set debug mode on all checks that support it
	for _, check := range allChecks {
		if debuggable, ok := check.(checks.Debuggable); ok {
			debuggable.SetDebug(debugMode)
			DebugLog("Enabled debug mode for check: %s", check.Name())
		}
	}

	fmt.Printf("Starting forensic analysis with %d checks...\n\n", len(allChecks))

	// Run all checks
	var suspiciousCount, errorCount, okCount int
	allResults := make([]struct {
		check  checks.Check
		result checks.Result
	}, 0)

	for i, check := range allChecks {
		fmt.Printf("[%d/%d] Running: %s\n", i+1, len(allChecks), check.Name())
		fmt.Printf("        %s\n", check.Description())

		DebugLog(strings.Repeat("=", 60))
		DebugLog("Starting check [%d/%d]: %s", i+1, len(allChecks), check.Name())
		DebugLog("Description: %s", check.Description())
		checkStart := time.Now()

		result, err := check.Run()

		DebugLog("Check completed in %.3fs", time.Since(checkStart).Seconds())
		allResults = append(allResults, struct {
			check  checks.Check
			result checks.Result
		}{check: check, result: result})

		// Print immediate result
		statusSymbol := getStatusSymbol(result.Status)
		fmt.Printf("        %s %s (%.2fs)\n", statusSymbol, result.Message, result.Duration.Seconds())

		// Show findings immediately
		if len(result.Findings) > 0 {
			for _, finding := range result.Findings {
				fmt.Printf("          ⚠️  %s\n", finding.Description)
				if len(finding.Details) > 0 {
					for key, value := range finding.Details {
						fmt.Printf("              - %s: %s\n", key, value)
					}
				}
			}
		}

		if err != nil {
			fmt.Printf("        ⚠️  Error: %v\n", err)
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
	fmt.Println("SUMMARY REPORT")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Total Checks: %d\n", len(allChecks))
	fmt.Printf("  ✅ OK:         %d\n", okCount)
	fmt.Printf("  🔍 SUSPICIOUS: %d\n", suspiciousCount)
	fmt.Printf("  ❌ ERROR:      %d\n", errorCount)
	fmt.Println()

	// Print detailed findings if any
	totalFindings := 0
	for _, ar := range allResults {
		totalFindings += len(ar.result.Findings)
	}

	if totalFindings > 0 {
		fmt.Println("DETAILED FINDINGS:")
		fmt.Println(strings.Repeat("-", 70))
		for _, ar := range allResults {
			if len(ar.result.Findings) > 0 {
				fmt.Printf("\n%s:\n", ar.check.Name())
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

	// Cleanup all checks
	DebugLog("Starting cleanup phase...")
	fmt.Println("Cleaning up...")
	for _, check := range allChecks {
		DebugLog("Cleaning up check: %s", check.Name())
		if err := check.Cleanup(); err != nil {
			fmt.Printf("  Warning: Failed to cleanup %s: %v\n", check.Name(), err)
			DebugLog("Cleanup error for %s: %v", check.Name(), err)
		} else {
			DebugLog("Successfully cleaned up: %s", check.Name())
		}
	}
	DebugLog("Cleanup phase completed")

	// Exit with appropriate code
	if suspiciousCount > 0 {
		fmt.Println(strings.Repeat("=", 70))
		fmt.Println("⚠️  ALERT: Suspicious activity detected!")
		fmt.Println("   Your system may be compromised. Review findings above.")
		fmt.Println(strings.Repeat("=", 70))
		os.Exit(2)
	} else if errorCount > 0 {
		fmt.Println(strings.Repeat("=", 70))
		fmt.Println("⚠️  WARNING: Some checks failed to complete")
		fmt.Println(strings.Repeat("=", 70))
		os.Exit(1)
	} else {
		fmt.Println(strings.Repeat("=", 70))
		fmt.Println("✅ System appears clean - no rootkit activity detected")
		fmt.Println(strings.Repeat("=", 70))
		os.Exit(0)
	}
}

// getStatusSymbol returns an emoji/symbol for the status
func getStatusSymbol(status checks.Status) string {
	switch status {
	case checks.StatusOK:
		return "✅"
	case checks.StatusSuspicious:
		return "🔍"
	case checks.StatusError:
		return "❌"
	default:
		return "❓"
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
