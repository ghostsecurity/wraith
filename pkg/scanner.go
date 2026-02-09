package wraith

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Scanner wraps OSV-Scanner functionality
type Scanner struct {
	binaryPath string
	timeout    time.Duration
}

// ScanOptions configures the scanning behavior
type ScanOptions struct {
	// Offline mode - scan without network access
	Offline            bool
	DownloadOfflineDBs bool // Download/refresh local DB before offline scan

	// Custom config file
	ConfigFile string

	// License scanning
	Licenses         bool     // Enable license scanning
	LicenseAllowlist []string // Allowlist of permitted licenses (e.g., "MIT", "Apache-2.0")
}

// ScanOption is a functional option for configuring scans
type ScanOption func(*ScanOptions)

// WithOffline enables offline scanning mode (no network requests)
func WithOffline() ScanOption {
	return func(o *ScanOptions) { o.Offline = true }
}

// WithOfflineDownload downloads/refreshes the local vulnerability database
func WithOfflineDownload() ScanOption {
	return func(o *ScanOptions) { o.DownloadOfflineDBs = true }
}

// WithConfigFile specifies a custom osv-scanner config file
func WithConfigFile(path string) ScanOption {
	return func(o *ScanOptions) { o.ConfigFile = path }
}

// WithLicenses enables license scanning with summary
func WithLicenses() ScanOption {
	return func(o *ScanOptions) { o.Licenses = true }
}

// WithLicenseAllowlist enables license scanning with an allowlist
func WithLicenseAllowlist(licenses ...string) ScanOption {
	return func(o *ScanOptions) {
		o.Licenses = true
		o.LicenseAllowlist = licenses
	}
}

// NewScanner creates a new scanner instance
// It will look for osv-scanner in the following order:
// 1. Provided binary path (if specified)
// 2. Same directory as the wraith executable (bundled)
// 3. System PATH
func NewScanner(binaryPath ...string) (*Scanner, error) {
	var path string

	if len(binaryPath) > 0 && binaryPath[0] != "" {
		path = binaryPath[0]
	} else {
		// First, try to find bundled osv-scanner next to the executable
		if execPath, err := os.Executable(); err == nil {
			bundledPath := filepath.Join(filepath.Dir(execPath), "osv-scanner")
			if _, err := os.Stat(bundledPath); err == nil {
				path = bundledPath
			}
		}

		// Fall back to PATH if bundled binary not found
		if path == "" {
			var err error
			path, err = exec.LookPath("osv-scanner")
			if err != nil {
				return nil, fmt.Errorf("osv-scanner not found (install it or place it next to wraith): %w", err)
			}
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

	// Build base args
	args := []string{"scan", "source", "--lockfile", absPath, "--format", "json"}

	// Add offline mode flags
	if opts.DownloadOfflineDBs {
		args = append(args, "--download-offline-databases")
	}
	if opts.Offline {
		args = append(args, "--offline")
	}

	// Add custom config file
	if opts.ConfigFile != "" {
		args = append(args, "--config="+opts.ConfigFile)
	}

	// Add license scanning flags
	if opts.Licenses {
		if len(opts.LicenseAllowlist) > 0 {
			args = append(args, "--licenses="+strings.Join(opts.LicenseAllowlist, ","))
		} else {
			args = append(args, "--licenses")
		}
	}

	cmd := exec.CommandContext(ctx, s.binaryPath, args...)

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

// DownloadDB downloads or refreshes the local vulnerability database for offline scanning
func (s *Scanner) DownloadDB() error {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	// osv-scanner requires a scan target even when just downloading the database
	// We scan the current directory with offline mode to trigger the download
	cmd := exec.CommandContext(ctx, s.binaryPath,
		"scan", "source",
		"--offline",
		"--download-offline-databases",
		".",
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("database download timed out after %v", s.timeout)
		}
		// Ignore exit code 1 (vulnerabilities found) - we only care about the download
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil
		}
		return fmt.Errorf("failed to download database: %s", stderr.String())
	}

	return nil
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
