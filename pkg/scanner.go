package wraith

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Scanner wraps OSV-Scanner functionality
type Scanner struct {
	binaryPath string
	timeout    time.Duration
}

// ScanOptions configures the scanning behavior
type ScanOptions struct {
	// Future options can be added here
	// TODO: Add support for offline mode
	// TODO: Add support for custom config files
	// TODO: Add support for license scanning
}

// ScanOption is a functional option for configuring scans
type ScanOption func(*ScanOptions)

// NewScanner creates a new scanner instance
// It will look for osv-scanner in PATH or use the provided binary path
func NewScanner(binaryPath ...string) (*Scanner, error) {
	var path string

	if len(binaryPath) > 0 && binaryPath[0] != "" {
		path = binaryPath[0]
	} else {
		// Look for osv-scanner in PATH
		var err error
		path, err = exec.LookPath("osv-scanner")
		if err != nil {
			return nil, fmt.Errorf("osv-scanner not found in PATH: %w", err)
		}
	}

	// Verify the binary exists and is executable
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("osv-scanner binary not found at %s: %w", path, err)
	}

	return &Scanner{
		binaryPath: path,
		timeout:    5 * time.Minute, // Default timeout
	}, nil
}

// ScanLockfile scans a specific lockfile and returns the results
// This is the core function that always uses JSON output format
func (s *Scanner) ScanLockfile(lockfilePath string, options ...ScanOption) (*OSVScanResult, error) {
	// Validate lockfile exists
	if _, err := os.Stat(lockfilePath); err != nil {
		return nil, fmt.Errorf("lockfile not found: %w", err)
	}

	// Get absolute path for consistency
	absPath, err := filepath.Abs(lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Apply options (currently unused but ready for future expansion)
	opts := &ScanOptions{}
	for _, option := range options {
		option(opts)
	}

	// Build command
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	// Always use JSON format and scan the specific lockfile
	// OSV-Scanner command structure: osv-scanner scan source --lockfile <path> --format json
	cmd := exec.CommandContext(ctx, s.binaryPath,
		"scan", "source",
		"--lockfile", absPath,
		"--format", "json",
	)

	// Execute command and capture stdout/stderr separately
	output, err := s.executeOSVScanner(ctx, cmd)
	if err != nil {
		return nil, err
	}

	// Parse JSON output
	var result OSVScanResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse osv-scanner output: %w", err)
	}

	return &result, nil
}

// SetTimeout sets the timeout for scanner operations
func (s *Scanner) SetTimeout(timeout time.Duration) {
	s.timeout = timeout
}

// GetBinaryPath returns the path to the osv-scanner binary being used
func (s *Scanner) GetBinaryPath() string {
	return s.binaryPath
}

// executeOSVScanner handles the actual command execution and manages OSV-scanner's exit code behavior
// OSV-scanner exits with code 1 when vulnerabilities are found, but still provides valid JSON output
func (s *Scanner) executeOSVScanner(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
	// Capture stdout and stderr separately
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := stdout.Bytes()

	if err != nil {
		// Handle different types of errors
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("scan timed out after %v", s.timeout)
		}

		if _, ok := err.(*exec.ExitError); ok {
			// OSV-scanner exits with code 1 when vulnerabilities are found
			// Check if we got valid JSON output despite the exit code
			if len(output) > 0 && s.isValidJSON(output) {
				// Valid JSON found, return the output despite exit code
				return output, nil
			}
			return nil, fmt.Errorf("osv-scanner failed: %s", stderr.String())
		}

		return nil, fmt.Errorf("failed to execute osv-scanner: %w", err)
	}

	return output, nil
}

// isValidJSON checks if the provided bytes contain valid JSON by attempting to parse into OSVScanResult
func (s *Scanner) isValidJSON(data []byte) bool {
	var testResult OSVScanResult
	return json.Unmarshal(data, &testResult) == nil
}

// QuickScan is a convenience function for simple scanning
// It creates a scanner and scans the lockfile in one call
func QuickScan(lockfilePath string) (*OSVScanResult, error) {
	scanner, err := NewScanner()
	if err != nil {
		return nil, err
	}

	return scanner.ScanLockfile(lockfilePath)
}
