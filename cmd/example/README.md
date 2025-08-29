# Wraith Library Example

This example demonstrates how to import and use the wraith library.

## Running the Example

### Quick Start

```bash
go run ./cmd/example/main.go
```

### Scan a Specific Lockfile

```bash
# Scan a specific lockfile
go run ./cmd/example/main.go /path/to/go.mod
go run ./cmd/example/main.go /path/to/poetry.lock
go run ./cmd/example/main.go /path/to/yarn.lock
```

## What the Example Demonstrates

### 1. Quick Scan (Simplest Usage)

```go
result, err := wraith.QuickScan("go.mod")
```

### 2. Advanced Scanner Usage

```go
scanner, err := wraith.NewScanner()
scanner.SetTimeout(2 * time.Minute)
result, err := scanner.ScanLockfile("go.mod")
```

### 3. Detailed Vulnerability Analysis

- Package information
- Vulnerability details
- Severity levels
- CVE extraction

### 4. Simplified Results for Pipeline Integration

```go
simplified := result.ToSimplifiedResults()
```

## Expected Output

The example will show:

- Scan timing and performance
- Package and vulnerability counts
- Detailed vulnerability information
- Pipeline-ready simplified output
- Exit codes (0 = clean, 1 = vulnerabilities found)

## Integration Pattern

This example shows the recommended pattern for integrating wraith into your analysis pipeline:

1. **Quick Scan**: For simple vulnerability detection
2. **Advanced Scanner**: For custom timeouts and configuration
3. **Detailed Analysis**: For security reporting
4. **Simplified Output**: For logging and alerting systems

## Requirements

- Go 1.24.3+
- OSV-Scanner in PATH (`brew install osv-scanner`)
- A lockfile to scan (go.mod, poetry.lock, etc.)
