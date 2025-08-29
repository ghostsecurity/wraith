package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	wraith "github.com/ghostsecurity/wraith/pkg"
)

func main() {
	var lockfilePath string
	if len(os.Args) > 1 {
		lockfilePath = os.Args[1]
	}

	absPath, err := filepath.Abs(lockfilePath)
	if err != nil {
		log.Fatalf("Failed to resolve path: %v", err)
	}

	fmt.Printf("Scanning lockfile: %s\n\n", absPath)

	// Example 1: Quick Scan (simplest usage)
	fmt.Println("Example 1: Quick Scan")
	fmt.Println("--------------------")

	start := time.Now()
	result, err := wraith.QuickScan(lockfilePath)
	if err != nil {
		log.Fatalf("❌ Quick scan failed: %v", err)
	}
	duration := time.Since(start)

	fmt.Printf("✅ Scan completed in %v\n", duration)
	fmt.Printf("📦 Found %d packages\n", result.GetPackageCount())
	fmt.Printf("🚨 Found %d vulnerabilities\n\n", result.GetVulnerabilityCount())

	// Example 2: Advanced Scanner Usage
	fmt.Println("Example 2: Advanced Scanner Usage")
	fmt.Println("--------------------------------")

	scanner, err := wraith.NewScanner()
	if err != nil {
		log.Fatalf("❌ Failed to create scanner: %v", err)
	}

	fmt.Printf("🔧 Scanner binary: %s\n", scanner.GetBinaryPath())

	// Set custom timeout
	// scanner.SetTimeout(2 * time.Minute)
	scanner.SetTimeout(30 * time.Second)

	// Scan with advanced scanner
	start = time.Now()
	_, err = scanner.ScanLockfile(lockfilePath)
	if err != nil {
		log.Fatalf("❌ Advanced scan failed: %v", err)
	}
	duration = time.Since(start)

	fmt.Printf("Advanced scan completed in %v\n\n", duration)

	// Example 3: Detailed Vulnerability Analysis
	fmt.Println("Example 3: Detailed Vulnerability Analysis")
	fmt.Println("------------------------------------------")

	vulnPackages := result.GetPackagesWithVulnerabilities()
	if len(vulnPackages) == 0 {
		fmt.Println("🎉 No vulnerabilities found!")
	} else {
		for i, pkg := range vulnPackages {
			fmt.Printf("\n📦 Package %d: %s v%s (%s)\n",
				i+1, pkg.Package.Name, pkg.Package.Version, pkg.Package.Ecosystem)

			for j, vuln := range pkg.Vulnerabilities {
				fmt.Printf("  🚨 Vulnerability %d: %s\n", j+1, vuln.ID)
				if vuln.Summary != "" {
					fmt.Printf("\t- %s\n", vuln.Summary)
				}

				// Show severity if available
				if len(vuln.Severity) > 0 {
					fmt.Printf("\t- Severity: %s\n", vuln.Severity[0].Type)
				}

				// Show CVEs if available
				cves := extractCVEs(vuln.Aliases)
				if len(cves) > 0 {
					fmt.Printf("\t- CVEs: %v\n", cves)
				}
			}
		}
	}

	// Example 4: Simplified Results for Pipeline Integration
	fmt.Println("\n\nExample 4: Simplified Results (Pipeline-Ready)")
	fmt.Println("----------------------------------------------")

	simplified := result.ToSimplifiedResults()
	for _, pkg := range simplified {
		if len(pkg.FoundVulnerabilities) > 0 {
			fmt.Printf("ALERT: %s v%s (%s) has %d vulnerabilities\n",
				pkg.Package, pkg.Version, pkg.Ecosystem, len(pkg.FoundVulnerabilities))

			for _, vuln := range pkg.FoundVulnerabilities {
				fmt.Printf("  - %s: %s\n", vuln.ID, vuln.Summary)
			}
		}
	}

	// Summary
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("📊 SCAN SUMMARY")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("Total Packages: %d\n", result.GetPackageCount())
	fmt.Printf("Vulnerable Packages: %d\n", len(vulnPackages))
	fmt.Printf("Total Vulnerabilities: %d\n", result.GetVulnerabilityCount())

	if result.GetVulnerabilityCount() > 0 {
		fmt.Println("\n⚠️  Action Required: Review and address vulnerabilities above")
		os.Exit(1)
	} else {
		fmt.Println("\n✅ All clear! No vulnerabilities detected")
	}
}

// Helper function to extract CVEs from aliases
func extractCVEs(aliases []string) []string {
	var cves []string
	for _, alias := range aliases {
		if len(alias) >= 4 && alias[:4] == "CVE-" {
			cves = append(cves, alias)
		}
	}
	return cves
}
