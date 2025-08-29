package wraith

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestOSVScanResultParsing(t *testing.T) {
	testCases := []struct {
		name     string
		filename string
	}{
		{"Gemfile sample", "sample_output_gemfile.json"},
		{"Poetry sample", "sample_output_poetry.json"},
		{"UV sample", "sample_output_uv.json"},
		{"Go sample", "sample_output_go.json"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Read the sample file
			filePath := filepath.Join("testdata", "output", tc.filename)
			data, err := os.ReadFile(filePath)
			if err != nil {
				t.Fatalf("Failed to read %s: %v", tc.filename, err)
			}

			// Parse into our struct
			var result OSVScanResult
			err = json.Unmarshal(data, &result)
			if err != nil {
				t.Fatalf("Failed to parse %s: %v", tc.filename, err)
			}

			// Basic validation
			if len(result.Results) == 0 {
				t.Errorf("Expected at least one result, got 0")
			}

			// Validate first result structure
			firstResult := result.Results[0]
			if firstResult.Source.Path == "" {
				t.Errorf("Expected source path to be set")
			}
			if firstResult.Source.Type == "" {
				t.Errorf("Expected source type to be set")
			}

			// Check packages
			if len(firstResult.Packages) == 0 {
				t.Errorf("Expected at least one package, got 0")
			}

			// Validate first package
			firstPackage := firstResult.Packages[0]
			if firstPackage.Package.Name == "" {
				t.Errorf("Expected package name to be set")
			}
			if firstPackage.Package.Version == "" {
				t.Errorf("Expected package version to be set")
			}
			if firstPackage.Package.Ecosystem == "" {
				t.Errorf("Expected package ecosystem to be set")
			}

			// Check for vulnerabilities (should exist in our test data)
			if len(firstPackage.Vulnerabilities) == 0 {
				t.Errorf("Expected at least one vulnerability in test data")
			}

			// Validate first vulnerability if it exists
			if len(firstPackage.Vulnerabilities) > 0 {
				vuln := firstPackage.Vulnerabilities[0]
				if vuln.ID == "" {
					t.Errorf("Expected vulnerability ID to be set")
				}
				if vuln.Summary == "" && vuln.Details == "" {
					t.Errorf("Expected either summary or details to be set")
				}
			}

			t.Logf("Successfully parsed %s: %d sources, %d packages in first source",
				tc.filename, len(result.Results), len(firstResult.Packages))
		})
	}
}

func TestVulnerabilityGroupParsing(t *testing.T) {
	// Test parsing of vulnerability groups specifically
	filePath := filepath.Join("testdata", "output", "sample_output_gemfile.json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read sample file: %v", err)
	}

	var result OSVScanResult
	err = json.Unmarshal(data, &result)
	if err != nil {
		t.Fatalf("Failed to parse sample file: %v", err)
	}

	// Find a package with groups
	var foundGroups bool
	for _, source := range result.Results {
		for _, pkg := range source.Packages {
			if len(pkg.Groups) > 0 {
				foundGroups = true
				group := pkg.Groups[0]

				if len(group.IDs) == 0 {
					t.Errorf("Expected group to have at least one ID")
				}
				if group.MaxSeverity == "" {
					t.Errorf("Expected group to have max severity")
				}

				t.Logf("Found group with %d IDs, %d aliases, max severity: %s",
					len(group.IDs), len(group.Aliases), group.MaxSeverity)
				break
			}
		}
		if foundGroups {
			break
		}
	}

	if !foundGroups {
		t.Errorf("Expected to find at least one vulnerability group in test data")
	}
}

func TestSeverityInfoParsing(t *testing.T) {
	// Test parsing of different severity types
	filePath := filepath.Join("testdata", "output", "sample_output_uv.json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read sample file: %v", err)
	}

	var result OSVScanResult
	err = json.Unmarshal(data, &result)
	if err != nil {
		t.Fatalf("Failed to parse sample file: %v", err)
	}

	// Find vulnerabilities with severity info
	var foundSeverity bool
	for _, source := range result.Results {
		for _, pkg := range source.Packages {
			for _, vuln := range pkg.Vulnerabilities {
				if len(vuln.Severity) > 0 {
					foundSeverity = true
					severity := vuln.Severity[0]

					if severity.Type == "" {
						t.Errorf("Expected severity type to be set")
					}
					if severity.Score == "" {
						t.Errorf("Expected severity score to be set")
					}

					t.Logf("Found severity: type=%s, score=%s", severity.Type, severity.Score)
					break
				}
			}
			if foundSeverity {
				break
			}
		}
		if foundSeverity {
			break
		}
	}

	if !foundSeverity {
		t.Errorf("Expected to find at least one severity entry in test data")
	}
}
