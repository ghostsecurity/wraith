package wraith

import "time"

// OSVScanResult represents the complete output from OSV-Scanner
type OSVScanResult struct {
	Results            []SourceResult      `json:"results"`
	ExperimentalConfig *ExperimentalConfig `json:"experimental_config,omitempty"`
	LicenseSummary     []LicenseSummary    `json:"license_summary,omitempty"`
}

// LicenseSummary represents license count information
type LicenseSummary struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// SourceResult represents scan results for a single source (lockfile, directory, etc.)
type SourceResult struct {
	Source   Source          `json:"source"`
	Packages []PackageResult `json:"packages"`
}

// Source represents the scanned source information
type Source struct {
	Path string `json:"path"`
	Type string `json:"type"` // e.g., "lockfile", "directory"
}

// PackageResult represents vulnerability information for a single package
type PackageResult struct {
	Package           Package              `json:"package"`
	Vulnerabilities   []Vulnerability      `json:"vulnerabilities,omitempty"`
	Groups            []VulnerabilityGroup `json:"groups,omitempty"`
	Licenses          []string             `json:"licenses,omitempty"`
	LicenseViolations []string             `json:"license_violations,omitempty"`
}

// Package represents basic package information
type Package struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"` // e.g., "PyPI", "RubyGems", "npm", "Go"
	PURL      string `json:"purl,omitempty"`
}

// Vulnerability represents a detailed vulnerability record
type Vulnerability struct {
	Modified         time.Time              `json:"modified"`
	Published        time.Time              `json:"published"`
	SchemaVersion    string                 `json:"schema_version"`
	ID               string                 `json:"id"`
	Aliases          []string               `json:"aliases,omitempty"`
	Related          []string               `json:"related,omitempty"`
	Summary          string                 `json:"summary,omitempty"`
	Details          string                 `json:"details,omitempty"`
	Severity         []SeverityInfo         `json:"severity,omitempty"`
	Affected         []AffectedPackage      `json:"affected,omitempty"`
	References       []Reference            `json:"references,omitempty"`
	DatabaseSpecific map[string]interface{} `json:"database_specific,omitempty"`
}

// VulnerabilityGroup represents grouped vulnerability information
type VulnerabilityGroup struct {
	IDs         []string `json:"ids"`
	Aliases     []string `json:"aliases,omitempty"`
	MaxSeverity string   `json:"max_severity,omitempty"`
}

// SeverityInfo represents vulnerability severity scoring
type SeverityInfo struct {
	Type  string `json:"type"`  // e.g., "CVSS_V3", "CVSS_V4"
	Score string `json:"score"` // e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
}

// AffectedPackage represents affected package version ranges
type AffectedPackage struct {
	Package          Package                `json:"package"`
	Ranges           []VersionRange         `json:"ranges,omitempty"`
	Versions         []string               `json:"versions,omitempty"`
	DatabaseSpecific map[string]interface{} `json:"database_specific,omitempty"`
}

// VersionRange represents a range of affected versions
type VersionRange struct {
	Type   string       `json:"type"` // e.g., "ECOSYSTEM"
	Events []RangeEvent `json:"events"`
}

// RangeEvent represents version range events (introduced, fixed)
type RangeEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// Reference represents a vulnerability reference link
type Reference struct {
	Type string `json:"type"` // e.g., "WEB", "ADVISORY", "REPORT", "PACKAGE"
	URL  string `json:"url"`
}

// ExperimentalConfig represents experimental configuration from OSV-Scanner
type ExperimentalConfig struct {
	Licenses *LicenseConfig `json:"licenses,omitempty"`
}

// LicenseConfig represents license scanning configuration
type LicenseConfig struct {
	Summary   bool     `json:"summary"`
	Allowlist []string `json:"allowlist"`
}

// Legacy types for backward compatibility and simplified usage

// ScanResult provides a simplified view of scan results
type ScanResult struct {
	Package              string
	Version              string
	Ecosystem            string
	FoundVulnerabilities []VulnerabilityInfo
}

// VulnerabilityInfo provides simplified vulnerability information
type VulnerabilityInfo struct {
	ID         string
	Summary    string
	Details    string
	Severity   string
	CVEs       []string
	References []string
}
