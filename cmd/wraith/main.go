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

func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	format := fs.String("format", "text", "Output format: text, json, md")
	outputFile := fs.String("output", "", "Write output to file (implies --format md if .md extension)")
	noColor := fs.Bool("no-color", false, "Disable colored output (text format only)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: wraith scan [options] <lockfile>\n\n")
		fmt.Fprintf(os.Stderr, "Scan a lockfile for known vulnerabilities.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  wraith scan go.mod                    # Text output to terminal\n")
		fmt.Fprintf(os.Stderr, "  wraith scan go.mod --format json      # JSON output to stdout\n")
		fmt.Fprintf(os.Stderr, "  wraith scan go.mod --format md        # Markdown output to stdout\n")
		fmt.Fprintf(os.Stderr, "  wraith scan go.mod --output report.md # Write markdown to file\n")
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

	result, err := wraith.QuickScan(lockfile)
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
		PackageCount       int                 `json:"package_count"`
		VulnerabilityCount int                 `json:"vulnerability_count"`
		Results            []wraith.ScanResult `json:"results"`
	}{
		PackageCount:       result.GetPackageCount(),
		VulnerabilityCount: result.GetVulnerabilityCount(),
		Results:            result.ToSimplifiedResults(),
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error encoding JSON: %v\n", err), 1
	}

	exitCode := 0
	if result.GetVulnerabilityCount() > 0 {
		exitCode = 1
	}
	return string(data) + "\n", exitCode
}

func formatMarkdown(result *wraith.OSVScanResult, lockfile string) (string, int) {
	var sb strings.Builder
	pkgCount := result.GetPackageCount()
	vulnCount := result.GetVulnerabilityCount()
	vulnPackages := result.GetPackagesWithVulnerabilities()

	sb.WriteString("# Vulnerability Scan Report\n\n")
	sb.WriteString(fmt.Sprintf("**Scanned:** `%s`  \n", lockfile))
	sb.WriteString(fmt.Sprintf("**Date:** %s  \n\n", time.Now().Format("2006-01-02 15:04:05")))

	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("| Metric | Count |\n"))
	sb.WriteString(fmt.Sprintf("|--------|-------|\n"))
	sb.WriteString(fmt.Sprintf("| Packages scanned | %d |\n", pkgCount))
	sb.WriteString(fmt.Sprintf("| Vulnerabilities found | %d |\n", vulnCount))
	sb.WriteString(fmt.Sprintf("| Affected packages | %d |\n\n", len(vulnPackages)))

	if vulnCount == 0 {
		sb.WriteString("✅ **No vulnerabilities found!**\n")
		return sb.String(), 0
	}

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

	return sb.String(), 1
}

func formatText(result *wraith.OSVScanResult, useColor bool) (string, int) {
	var sb strings.Builder
	pkgCount := result.GetPackageCount()
	vulnCount := result.GetVulnerabilityCount()
	vulnPackages := result.GetPackagesWithVulnerabilities()

	sb.WriteString(fmt.Sprintf("\n%s\n", divider(50)))
	sb.WriteString(fmt.Sprintf("%s SCAN SUMMARY %s\n", bold("", useColor), ""))
	sb.WriteString(fmt.Sprintf("%s\n\n", divider(50)))

	sb.WriteString(fmt.Sprintf("Packages scanned: %s\n", bold(fmt.Sprintf("%d", pkgCount), useColor)))

	if vulnCount == 0 {
		sb.WriteString(fmt.Sprintf("Vulnerabilities:  %s\n\n", green("0", useColor)))
		sb.WriteString(fmt.Sprintf("%s No vulnerabilities found!\n\n", green("✓", useColor)))
		return sb.String(), 0
	}

	sb.WriteString(fmt.Sprintf("Vulnerabilities:  %s\n", red(fmt.Sprintf("%d", vulnCount), useColor)))
	sb.WriteString(fmt.Sprintf("Affected packages: %s\n\n", red(fmt.Sprintf("%d", len(vulnPackages)), useColor)))

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

	sb.WriteString(fmt.Sprintf("%s Review and address the vulnerabilities above.\n\n", yellow("!", useColor)))
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
    scan      Scan a lockfile for vulnerabilities
    version   Print version information
    help      Show this help message

EXAMPLES:
    wraith scan go.mod
    wraith scan poetry.lock --format json
    wraith scan go.mod --format md
    wraith scan go.mod --output report.md

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
