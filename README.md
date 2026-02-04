![Wraith Logo](./docs/wraith.png)

# Wraith - Resurrected

A vulnerability scanner for package dependencies.

## Features

A wrapper around [osv-scanner](https://github.com/google/osv-scanner) with a user-friendly CLI and Go library. The CLI release bundles osv-scanner, so you only need to do one install.

## CLI Installation

Download the latest release for your platform from the [releases page](https://github.com/ghostsecurity/wraith/releases).

```bash
# macOS (Apple Silicon)
curl -L https://github.com/ghostsecurity/wraith/releases/latest/download/wraith_darwin_arm64.tar.gz | tar xz
sudo mv wraith osv-scanner /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/ghostsecurity/wraith/releases/latest/download/wraith_darwin_amd64.tar.gz | tar xz
sudo mv wraith osv-scanner /usr/local/bin/

# Linux (x86_64)
curl -L https://github.com/ghostsecurity/wraith/releases/latest/download/wraith_linux_amd64.tar.gz | tar xz
sudo mv wraith osv-scanner /usr/local/bin/

# Linux (ARM64)
curl -L https://github.com/ghostsecurity/wraith/releases/latest/download/wraith_linux_arm64.tar.gz | tar xz
sudo mv wraith osv-scanner /usr/local/bin/
```

For Windows, download the `.zip` file from the releases page and extract both `wraith.exe` and `osv-scanner.exe` to a directory in your PATH.

## CLI Usage

```bash
# Scan a lockfile (text output)
wraith scan go.mod

# Output as JSON
wraith scan go.mod --format json

# Output as Markdown
wraith scan go.mod --format md

# Write Markdown report to file
wraith scan go.mod --output report.md
```

### Exit Codes

- `0`: No vulnerabilities found
- `1`: Vulnerabilities found or error occurred

## Library Installation

```bash
go get github.com/ghostsecurity/wraith
```

> **Note:** When using wraith as a library, you need [osv-scanner](https://github.com/google/osv-scanner) installed and available in your PATH.

## Library Usage

### Basic Usage

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

### Advanced Usage

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

### Pipeline Integration

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
