package wraith

import (
	"strings"
)

// ToSimplifiedResults converts OSVScanResult to a slice of simplified ScanResult structs
func (r *OSVScanResult) ToSimplifiedResults() []ScanResult {
	var results []ScanResult

	for _, source := range r.Results {
		for _, pkg := range source.Packages {
			if len(pkg.Vulnerabilities) > 0 {
				// Convert vulnerabilities to simplified format
				var vulnInfos []VulnerabilityInfo
				for _, vuln := range pkg.Vulnerabilities {
					vulnInfo := VulnerabilityInfo{
						ID:      vuln.ID,
						Summary: vuln.Summary,
						Details: vuln.Details,
						CVEs:    extractCVEs(vuln.Aliases),
					}

					// Extract severity score
					if len(vuln.Severity) > 0 {
						vulnInfo.Severity = vuln.Severity[0].Score
					}

					// Extract reference URLs
					for _, ref := range vuln.References {
						vulnInfo.References = append(vulnInfo.References, ref.URL)
					}

					vulnInfos = append(vulnInfos, vulnInfo)
				}

				result := ScanResult{
					Package:              pkg.Package.Name,
					Version:              pkg.Package.Version,
					Ecosystem:            pkg.Package.Ecosystem,
					FoundVulnerabilities: vulnInfos,
				}
				results = append(results, result)
			}
		}
	}

	return results
}

// extractCVEs extracts CVE identifiers from aliases
func extractCVEs(aliases []string) []string {
	var cves []string
	for _, alias := range aliases {
		if strings.HasPrefix(alias, "CVE-") {
			cves = append(cves, alias)
		}
	}
	return cves
}

// GetVulnerabilityCount returns the total number of vulnerabilities found
func (r *OSVScanResult) GetVulnerabilityCount() int {
	count := 0
	for _, source := range r.Results {
		for _, pkg := range source.Packages {
			count += len(pkg.Vulnerabilities)
		}
	}
	return count
}

// GetPackageCount returns the total number of packages scanned
func (r *OSVScanResult) GetPackageCount() int {
	count := 0
	for _, source := range r.Results {
		count += len(source.Packages)
	}
	return count
}

// GetPackagesWithVulnerabilities returns packages that have vulnerabilities
func (r *OSVScanResult) GetPackagesWithVulnerabilities() []PackageResult {
	var packages []PackageResult
	for _, source := range r.Results {
		for _, pkg := range source.Packages {
			if len(pkg.Vulnerabilities) > 0 {
				packages = append(packages, pkg)
			}
		}
	}
	return packages
}

// GetHighSeverityVulnerabilities returns vulnerabilities with high severity scores
func (r *OSVScanResult) GetHighSeverityVulnerabilities(minScore float64) []Vulnerability {
	var highSeverityVulns []Vulnerability

	for _, source := range r.Results {
		for _, pkg := range source.Packages {
			for _, vuln := range pkg.Vulnerabilities {
				// Check if any severity score meets the threshold
				for _, severity := range vuln.Severity {
					score := extractCVSSScore(severity.Score)
					if score >= minScore {
						highSeverityVulns = append(highSeverityVulns, vuln)
						break // Only add once per vulnerability
					}
				}
			}
		}
	}

	return highSeverityVulns
}

// extractCVSSScore extracts numeric score from CVSS string
// This is a simplified extraction - in production you might want more robust parsing
func extractCVSSScore(cvssString string) float64 {
	// Very basic extraction - look for patterns like "CVSS:3.1/..."
	// This is simplified - a real implementation would parse the full CVSS vector
	if strings.Contains(cvssString, "CVSS:3.1") || strings.Contains(cvssString, "CVSS:4.0") {
		// For now, return a default score - this would need proper CVSS parsing
		// to extract the actual numeric score
		return 5.0 // placeholder
	}
	return 0.0
}

// GetLicenseViolationCount returns the total number of license violations found
func (r *OSVScanResult) GetLicenseViolationCount() int {
	count := 0
	for _, source := range r.Results {
		for _, pkg := range source.Packages {
			count += len(pkg.LicenseViolations)
		}
	}
	return count
}

// GetPackagesWithLicenseViolations returns packages that have license violations
func (r *OSVScanResult) GetPackagesWithLicenseViolations() []PackageResult {
	var packages []PackageResult
	for _, source := range r.Results {
		for _, pkg := range source.Packages {
			if len(pkg.LicenseViolations) > 0 {
				packages = append(packages, pkg)
			}
		}
	}
	return packages
}

// HasLicenseViolations returns true if any license violations were found
func (r *OSVScanResult) HasLicenseViolations() bool {
	for _, source := range r.Results {
		for _, pkg := range source.Packages {
			if len(pkg.LicenseViolations) > 0 {
				return true
			}
		}
	}
	return false
}
