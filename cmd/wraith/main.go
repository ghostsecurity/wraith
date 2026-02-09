package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	wraith "github.com/ghostsecurity/wraith/pkg"
)

var (
	version = "dev"
)

const (
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		os.Exit(runScan(os.Args[2:]))
	case "download-db":
		os.Exit(runDownloadDB())
	case "version", "--version", "-v":
		fmt.Printf("wraith %s\n", version)
		os.Exit(0)
	case "help", "--help", "-h":
		printUsage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func runDownloadDB() int {
	fmt.Println("Downloading vulnerability database for offline scanning...")

	scanner, err := wraith.NewScanner()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Use a longer timeout for database download
	scanner.SetTimeout(10 * time.Minute)

	if err := scanner.DownloadDB(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	fmt.Println("Database downloaded successfully. You can now use --offline for scans.")
	return 0
}

func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	format := fs.String("format", "text", "Output format: text, json, md")
	outputFile := fs.String("output", "", "Write output to file (implies --format md if .md extension)")
	noColor := fs.Bool("no-color", false, "Disable colored output (text format only)")

	// Offline mode flags
	offline := fs.Bool("offline", false, "Scan using only local vulnerability database (no network)")
	downloadDB := fs.Bool("download-db", false, "Download/refresh local vulnerability database before scanning")

	// Config file flag
	configFile := fs.String("config", "", "Path to custom osv-scanner config file")

	// License scanning flags
	licenses := fs.Bool("licenses", false, "Enable license scanning")
	licenseAllowlist := fs.String("license-allowlist", "", "Comma-separated list of allowed licenses (e.g., MIT,Apache-2.0)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: wraith scan [options] <lockfile>\n\n")
		fmt.Fprintf(os.Stderr, "Scan a lockfile for known vulnerabilities.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  wraith scan go.mod                              # Text output to terminal\n")
		fmt.Fprintf(os.Stderr, "  wraith scan --format json go.mod                # JSON output to stdout\n")
		fmt.Fprintf(os.Stderr, "  wraith scan --format md go.mod                  # Markdown output to stdout\n")
		fmt.Fprintf(os.Stderr, "  wraith scan --output report.md go.mod           # Write markdown to file\n")
		fmt.Fprintf(os.Stderr, "  wraith scan --offline --download-db go.mod      # Offline scan with DB refresh\n")
		fmt.Fprintf(os.Stderr, "  wraith scan --config osv-scanner.toml go.mod    # Use custom config\n")
		fmt.Fprintf(os.Stderr, "  wraith scan --licenses go.mod                   # Include license info\n")
		fmt.Fprintf(os.Stderr, "  wraith scan --license-allowlist MIT,Apache-2.0 go.mod  # Check license violations\n")
	}

	if err := fs.Parse(args); err != nil {
		return 1
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: lockfile path is required\n\n")
		fs.Usage()
		return 1
	}

	lockfile := fs.Arg(0)
	outputFormat := *format

	// If output file has .md extension, default to markdown format
	if *outputFile != "" && strings.HasSuffix(*outputFile, ".md") && *format == "text" {
		outputFormat = "md"
	}

	useColor := !*noColor && isTerminal() && *outputFile == ""

	// Create scanner
	scanner, err := wraith.NewScanner()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Build scan options
	var options []wraith.ScanOption
	if *offline {
		options = append(options, wraith.WithOffline())
	}
	if *downloadDB {
		options = append(options, wraith.WithOfflineDownload())
	}
	if *configFile != "" {
		options = append(options, wraith.WithConfigFile(*configFile))
	}
	if *licenseAllowlist != "" {
		licenses := strings.Split(*licenseAllowlist, ",")
		options = append(options, wraith.WithLicenseAllowlist(licenses...))
	} else if *licenses {
		options = append(options, wraith.WithLicenses())
	}

	result, err := scanner.ScanLockfile(lockfile, options...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	var output string
	var exitCode int

	switch outputFormat {
	case "json":
		output, exitCode = formatJSON(result)
	case "md", "markdown":
		output, exitCode = formatMarkdown(result, lockfile)
	case "text":
		output, exitCode = formatText(result, useColor)
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown format %q (use text, json, or md)\n", outputFormat)
		return 1
	}

	// Write to file or stdout
	if *outputFile != "" {
		if err := os.WriteFile(*outputFile, []byte(output), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "Report written to %s\n", *outputFile)
	} else {
		fmt.Print(output)
	}

	return exitCode
}

func formatJSON(result *wraith.OSVScanResult) (string, int) {
	output := struct {
		PackageCount            int                     `json:"package_count"`
		VulnerabilityCount      int                     `json:"vulnerability_count"`
		LicenseViolationCount   int                     `json:"license_violation_count,omitempty"`
		LicenseSummary          []wraith.LicenseSummary `json:"license_summary,omitempty"`
		Results                 []wraith.ScanResult     `json:"results"`
		LicenseViolationDetails []licenseViolation      `json:"license_violations,omitempty"`
	}{
		PackageCount:            result.GetPackageCount(),
		VulnerabilityCount:      result.GetVulnerabilityCount(),
		LicenseViolationCount:   result.GetLicenseViolationCount(),
		LicenseSummary:          result.LicenseSummary,
		Results:                 result.ToSimplifiedResults(),
		LicenseViolationDetails: getLicenseViolations(result),
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error encoding JSON: %v\n", err), 1
	}

	exitCode := 0
	if result.GetVulnerabilityCount() > 0 || result.HasLicenseViolations() {
		exitCode = 1
	}
	return string(data) + "\n", exitCode
}

type licenseViolation struct {
	Package    string   `json:"package"`
	Version    string   `json:"version"`
	Licenses   []string `json:"licenses"`
	Violations []string `json:"violations"`
}

func getLicenseViolations(result *wraith.OSVScanResult) []licenseViolation {
	var violations []licenseViolation
	for _, pkg := range result.GetPackagesWithLicenseViolations() {
		violations = append(violations, licenseViolation{
			Package:    pkg.Package.Name,
			Version:    pkg.Package.Version,
			Licenses:   pkg.Licenses,
			Violations: pkg.LicenseViolations,
		})
	}
	return violations
}

func formatMarkdown(result *wraith.OSVScanResult, lockfile string) (string, int) {
	var sb strings.Builder
	pkgCount := result.GetPackageCount()
	vulnCount := result.GetVulnerabilityCount()
	vulnPackages := result.GetPackagesWithVulnerabilities()
	licenseViolationCount := result.GetLicenseViolationCount()
	licenseViolationPackages := result.GetPackagesWithLicenseViolations()

	sb.WriteString("# Vulnerability Scan Report\n\n")
	sb.WriteString(fmt.Sprintf("**Scanned:** `%s`  \n", lockfile))
	sb.WriteString(fmt.Sprintf("**Date:** %s  \n\n", time.Now().Format("2006-01-02 15:04:05")))

	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Metric | Count |\n")
	sb.WriteString("|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Packages scanned | %d |\n", pkgCount))
	sb.WriteString(fmt.Sprintf("| Vulnerabilities found | %d |\n", vulnCount))
	sb.WriteString(fmt.Sprintf("| Affected packages | %d |\n", len(vulnPackages)))
	if licenseViolationCount > 0 || len(result.LicenseSummary) > 0 {
		sb.WriteString(fmt.Sprintf("| License violations | %d |\n", licenseViolationCount))
	}
	sb.WriteString("\n")

	// License summary
	if len(result.LicenseSummary) > 0 {
		sb.WriteString("## License Summary\n\n")
		sb.WriteString("| License | Count |\n")
		sb.WriteString("|---------|-------|\n")
		for _, ls := range result.LicenseSummary {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", ls.Name, ls.Count))
		}
		sb.WriteString("\n")
	}

	hasIssues := vulnCount > 0 || licenseViolationCount > 0

	if !hasIssues {
		sb.WriteString("✅ **No issues found!**\n")
		return sb.String(), 0
	}

	// Vulnerabilities section
	if vulnCount > 0 {
		sb.WriteString("## Vulnerabilities\n\n")

		for _, pkg := range vulnPackages {
			sb.WriteString(fmt.Sprintf("### %s@%s\n\n", pkg.Package.Name, pkg.Package.Version))
			sb.WriteString(fmt.Sprintf("**Ecosystem:** %s\n\n", pkg.Package.Ecosystem))

			for _, vuln := range pkg.Vulnerabilities {
				sb.WriteString(fmt.Sprintf("#### %s\n\n", vuln.ID))

				if vuln.Summary != "" {
					sb.WriteString(fmt.Sprintf("%s\n\n", vuln.Summary))
				}

				// CVEs
				cves := extractCVEs(vuln.Aliases)
				if len(cves) > 0 {
					sb.WriteString(fmt.Sprintf("**CVEs:** %s\n\n", strings.Join(cves, ", ")))
				}

				// Severity
				if len(vuln.Severity) > 0 {
					sb.WriteString(fmt.Sprintf("**Severity:** `%s`\n\n", vuln.Severity[0].Score))
				}

				// References
				if len(vuln.References) > 0 {
					sb.WriteString("**References:**\n")
					for _, ref := range vuln.References {
						sb.WriteString(fmt.Sprintf("- [%s](%s)\n", ref.URL, ref.URL))
					}
					sb.WriteString("\n")
				}

				sb.WriteString("---\n\n")
			}
		}
	}

	// License violations section
	if licenseViolationCount > 0 {
		sb.WriteString("## License Violations\n\n")
		sb.WriteString("| Package | Version | License | Violation |\n")
		sb.WriteString("|---------|---------|---------|----------|\n")
		for _, pkg := range licenseViolationPackages {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
				pkg.Package.Name,
				pkg.Package.Version,
				strings.Join(pkg.Licenses, ", "),
				strings.Join(pkg.LicenseViolations, ", ")))
		}
		sb.WriteString("\n")
	}

	return sb.String(), 1
}

func formatText(result *wraith.OSVScanResult, useColor bool) (string, int) {
	var sb strings.Builder
	pkgCount := result.GetPackageCount()
	vulnCount := result.GetVulnerabilityCount()
	vulnPackages := result.GetPackagesWithVulnerabilities()
	licenseViolationCount := result.GetLicenseViolationCount()
	licenseViolationPackages := result.GetPackagesWithLicenseViolations()

	sb.WriteString(fmt.Sprintf("\n%s\n", divider(50)))
	sb.WriteString(fmt.Sprintf("%s SCAN SUMMARY %s\n", bold("", useColor), ""))
	sb.WriteString(fmt.Sprintf("%s\n\n", divider(50)))

	sb.WriteString(fmt.Sprintf("Packages scanned: %s\n", bold(fmt.Sprintf("%d", pkgCount), useColor)))

	// Show license summary if available
	if len(result.LicenseSummary) > 0 {
		sb.WriteString(fmt.Sprintf("\n%s License Summary %s\n", bold("", useColor), ""))
		for _, ls := range result.LicenseSummary {
			sb.WriteString(fmt.Sprintf("  %s: %d\n", ls.Name, ls.Count))
		}
		sb.WriteString("\n")
	}

	hasIssues := vulnCount > 0 || licenseViolationCount > 0

	if !hasIssues {
		sb.WriteString(fmt.Sprintf("Vulnerabilities:  %s\n", green("0", useColor)))
		if licenseViolationCount == 0 && len(result.LicenseSummary) > 0 {
			sb.WriteString(fmt.Sprintf("License violations: %s\n", green("0", useColor)))
		}
		sb.WriteString(fmt.Sprintf("\n%s No issues found!\n\n", green("✓", useColor)))
		return sb.String(), 0
	}

	if vulnCount > 0 {
		sb.WriteString(fmt.Sprintf("Vulnerabilities:  %s\n", red(fmt.Sprintf("%d", vulnCount), useColor)))
		sb.WriteString(fmt.Sprintf("Affected packages: %s\n", red(fmt.Sprintf("%d", len(vulnPackages)), useColor)))
	} else {
		sb.WriteString(fmt.Sprintf("Vulnerabilities:  %s\n", green("0", useColor)))
	}

	if licenseViolationCount > 0 {
		sb.WriteString(fmt.Sprintf("License violations: %s\n", red(fmt.Sprintf("%d", licenseViolationCount), useColor)))
	}
	sb.WriteString("\n")

	// Display vulnerabilities
	for _, pkg := range vulnPackages {
		sb.WriteString(fmt.Sprintf("%s %s %s (%s)\n",
			red("●", useColor),
			bold(pkg.Package.Name, useColor),
			cyan(pkg.Package.Version, useColor),
			pkg.Package.Ecosystem))

		for _, vuln := range pkg.Vulnerabilities {
			sb.WriteString(fmt.Sprintf("  %s %s\n", yellow("└─", useColor), vuln.ID))
			if vuln.Summary != "" {
				summary := vuln.Summary
				if len(summary) > 80 {
					summary = summary[:77] + "..."
				}
				sb.WriteString(fmt.Sprintf("     %s\n", summary))
			}

			cves := extractCVEs(vuln.Aliases)
			if len(cves) > 0 {
				sb.WriteString(fmt.Sprintf("     CVEs: %s\n", strings.Join(cves, ", ")))
			}
		}
		sb.WriteString("\n")
	}

	// Display license violations
	if licenseViolationCount > 0 {
		sb.WriteString(fmt.Sprintf("%s LICENSE VIOLATIONS %s\n\n", bold("", useColor), ""))
		for _, pkg := range licenseViolationPackages {
			sb.WriteString(fmt.Sprintf("%s %s %s\n",
				red("●", useColor),
				bold(pkg.Package.Name, useColor),
				cyan(pkg.Package.Version, useColor)))
			sb.WriteString(fmt.Sprintf("  License: %s\n", strings.Join(pkg.Licenses, ", ")))
			sb.WriteString(fmt.Sprintf("  Violation: %s\n\n", red(strings.Join(pkg.LicenseViolations, ", "), useColor)))
		}
	}

	sb.WriteString(fmt.Sprintf("%s Review and address the issues above.\n\n", yellow("!", useColor)))
	return sb.String(), 1
}

func extractCVEs(aliases []string) []string {
	var cves []string
	for _, alias := range aliases {
		if strings.HasPrefix(alias, "CVE-") {
			cves = append(cves, alias)
		}
	}
	return cves
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `wraith - Vulnerability scanner for package dependencies

USAGE:
    wraith <command> [options]

COMMANDS:
    scan         Scan a lockfile for vulnerabilities
    download-db  Download vulnerability database for offline scanning
    version      Print version information
    help         Show this help message

EXAMPLES:
    wraith scan go.mod
    wraith scan --format json poetry.lock
    wraith download-db && wraith scan --offline go.mod
    wraith scan --license-allowlist MIT,Apache-2.0 go.mod

Run 'wraith scan --help' for more information on the scan command.
`)
}

func isTerminal() bool {
	fileInfo, _ := os.Stdout.Stat()
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

func divider(n int) string {
	return strings.Repeat("─", n)
}

func red(s string, useColor bool) string {
	if useColor {
		return colorRed + s + colorReset
	}
	return s
}

func green(s string, useColor bool) string {
	if useColor {
		return colorGreen + s + colorReset
	}
	return s
}

func yellow(s string, useColor bool) string {
	if useColor {
		return colorYellow + s + colorReset
	}
	return s
}

func cyan(s string, useColor bool) string {
	if useColor {
		return colorCyan + s + colorReset
	}
	return s
}

func bold(s string, useColor bool) string {
	if useColor {
		return colorBold + s + colorReset
	}
	return s
}
