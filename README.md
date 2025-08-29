# Wraith

AI powered vulnerability scanner for package dependencies.

## Installation

```bash
go get github.com/ghostsecurity/wraith
```

## Basic Usage

```go
package main

import (
    "fmt"
    "log"

    "github.com/ghostsecurity/wraith/pkg"
)

func main() {
    // Quick scan - simplest usage
    result, err := wraith.QuickScan("go.mod")
    if err != nil {
        log.Fatalf("Scan failed: %v", err)
    }

    fmt.Printf("Found %d packages with %d vulnerabilities\n",
        result.GetPackageCount(),
        result.GetVulnerabilityCount())
}
```

## Advanced Usage

```go
package main

import (
    "fmt"
    "log"
    "time"

    "github.com/ghostsecurity/wraith/pkg"
)

func main() {
    // Create scanner with custom timeout
    scanner, err := wraith.NewScanner()
    if err != nil {
        log.Fatalf("Failed to create scanner: %v", err)
    }

    // Set custom timeout
    scanner.SetTimeout(10 * time.Minute)

    // Scan lockfile
    result, err := scanner.ScanLockfile("poetry.lock")
    if err != nil {
        log.Fatalf("Scan failed: %v", err)
    }

    // Process results
    for _, pkg := range result.GetPackagesWithVulnerabilities() {
        fmt.Printf("Package: %s v%s (%s)\n",
            pkg.Package.Name,
            pkg.Package.Version,
            pkg.Package.Ecosystem)

        for _, vuln := range pkg.Vulnerabilities {
            fmt.Printf("  🚨 %s: %s\n", vuln.ID, vuln.Summary)
        }
    }
}
```

## Pipeline Integration

```go
package main

import (
    "log"

    "github.com/ghostsecurity/wraith/pkg"
)

func analyzeLockfile(lockfilePath string) {
    result, err := wraith.QuickScan(lockfilePath)
    if err != nil {
        log.Printf("ERROR: Failed to scan %s: %v", lockfilePath, err)
        return
    }

    // Convert to simplified format for logging
    simplified := result.ToSimplifiedResults()
    for _, pkg := range simplified {
        for _, vuln := range pkg.FoundVulnerabilities {
            log.Printf("VULNERABILITY: %s in %s v%s (%s) - %s",
                vuln.ID, pkg.Package, pkg.Version, pkg.Ecosystem, vuln.Summary)
        }
    }

    if result.GetVulnerabilityCount() == 0 {
        log.Printf("INFO: No vulnerabilities found in %s", lockfilePath)
    }
}
```

## Requirements

- Go 1.24.3 or later
- OSV-Scanner binary in PATH (install: `brew install osv-scanner`)

## Supported Lockfiles

- `go.mod` (Go modules)
- `poetry.lock` (Python Poetry)
- `uv.lock` (Python UV)
- `yarn.lock` (Node.js Yarn)
- `Gemfile.lock` (Ruby)
- And many more supported by OSV-Scanner
