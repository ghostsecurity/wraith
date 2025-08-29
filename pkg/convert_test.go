package wraith

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestToSimplifiedResults(t *testing.T) {
	// Load test data
	filePath := filepath.Join("testdata", "output", "sample_output_gemfile.json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read test data: %v", err)
	}

	var result OSVScanResult
	err = json.Unmarshal(data, &result)
	if err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	// Convert to simplified format
	simplified := result.ToSimplifiedResults()

	// Validate results
	if len(simplified) == 0 {
		t.Errorf("Expected simplified results, got empty slice")
	}

	for _, sr := range simplified {
		if sr.Package == "" {
			t.Errorf("Expected package name to be set")
		}
		if sr.Version == "" {
			t.Errorf("Expected package version to be set")
		}
		if sr.Ecosystem == "" {
			t.Errorf("Expected ecosystem to be set")
		}
		if len(sr.FoundVulnerabilities) == 0 {
			t.Errorf("Expected vulnerabilities for package %s", sr.Package)
		}

		// Check vulnerabilities
		for _, vuln := range sr.FoundVulnerabilities {
			if vuln.ID == "" {
				t.Errorf("Expected vulnerability ID to be set")
			}
			// Summary or Details should be present
			if vuln.Summary == "" && vuln.Details == "" {
				t.Errorf("Expected either summary or details for vulnerability %s", vuln.ID)
			}
		}

		t.Logf("Package: %s v%s (%s) - %d vulnerabilities",
			sr.Package, sr.Version, sr.Ecosystem, len(sr.FoundVulnerabilities))
	}
}

func TestGetVulnerabilityCount(t *testing.T) {
	// Load test data
	filePath := filepath.Join("testdata", "output", "sample_output_uv.json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read test data: %v", err)
	}

	var result OSVScanResult
	err = json.Unmarshal(data, &result)
	if err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	// Test vulnerability count
	vulnCount := result.GetVulnerabilityCount()
	if vulnCount == 0 {
		t.Errorf("Expected vulnerability count > 0, got %d", vulnCount)
	}

	// Test package count
	pkgCount := result.GetPackageCount()
	if pkgCount == 0 {
		t.Errorf("Expected package count > 0, got %d", pkgCount)
	}

	t.Logf("Found %d vulnerabilities across %d packages", vulnCount, pkgCount)
}

func TestGetPackagesWithVulnerabilities(t *testing.T) {
	// Load test data
	filePath := filepath.Join("testdata", "output", "sample_output_poetry.json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read test data: %v", err)
	}

	var result OSVScanResult
	err = json.Unmarshal(data, &result)
	if err != nil {
		t.Fatalf("Failed to parse test data: %v", err)
	}

	// Get packages with vulnerabilities
	vulnPackages := result.GetPackagesWithVulnerabilities()

	if len(vulnPackages) == 0 {
		t.Errorf("Expected packages with vulnerabilities, got 0")
	}

	// Validate each package has vulnerabilities
	for _, pkg := range vulnPackages {
		if len(pkg.Vulnerabilities) == 0 {
			t.Errorf("Package %s should have vulnerabilities but has 0", pkg.Package.Name)
		}
		t.Logf("Package %s v%s has %d vulnerabilities",
			pkg.Package.Name, pkg.Package.Version, len(pkg.Vulnerabilities))
	}
}

func TestExtractCVEs(t *testing.T) {
	testCases := []struct {
		name     string
		aliases  []string
		expected []string
	}{
		{
			name:     "With CVEs",
			aliases:  []string{"CVE-2024-12345", "GHSA-xxxx-xxxx-xxxx", "CVE-2023-67890"},
			expected: []string{"CVE-2024-12345", "CVE-2023-67890"},
		},
		{
			name:     "No CVEs",
			aliases:  []string{"GHSA-xxxx-xxxx-xxxx", "PYSEC-2024-52"},
			expected: []string{},
		},
		{
			name:     "Empty aliases",
			aliases:  []string{},
			expected: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := extractCVEs(tc.aliases)

			if len(result) != len(tc.expected) {
				t.Errorf("Expected %d CVEs, got %d", len(tc.expected), len(result))
			}

			for i, cve := range result {
				if i < len(tc.expected) && cve != tc.expected[i] {
					t.Errorf("Expected CVE %s, got %s", tc.expected[i], cve)
				}
			}
		})
	}
}
