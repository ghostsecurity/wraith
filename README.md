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

### Verifying Release Signatures

All release artifacts are signed with [Sigstore cosign](https://github.com/sigstore/cosign) for supply chain security.

```bash
# Install cosign
brew install cosign  # macOS
# or download from https://github.com/sigstore/cosign/releases

# Verify a release artifact
cosign verify-blob wraith_linux_amd64.tar.gz \
  --bundle wraith_linux_amd64.tar.gz.sigstore.json \
  --certificate-identity-regexp 'https://github.com/ghostsecurity/wraith/.github/workflows/release.yml' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

## CLI Usage

```bash
# Scan a lockfile (text output)
wraith scan go.mod

# Output as JSON
wraith scan --format json go.mod

# Output as Markdown
wraith scan --format md go.mod

# Write Markdown report to file
wraith scan --output report.md go.mod
```

> **Note:** Flags must come before the lockfile path.

### Offline Mode

Wraith can scan without network access using a locally cached vulnerability database.

```bash
# Download the vulnerability database for offline use
wraith download-db

# Scan using only the local database (no network requests)
wraith scan --offline go.mod

# Download fresh database and scan in one command
wraith scan --offline --download-db go.mod
```

The database is stored in:
- Linux: `~/.cache/osv-scanner/`
- macOS: `~/Library/Caches/osv-scanner/`
- Windows: `%LOCALAPPDATA%\osv-scanner\`

### License Scanning

Check dependencies for license compliance.

```bash
# Show license information for all dependencies
wraith scan --licenses go.mod

# Enforce a license allowlist (fails if dependencies use other licenses)
wraith scan --license-allowlist MIT,Apache-2.0,BSD-3-Clause go.mod
```

When using `--license-allowlist`, the scan will fail (exit code 1) if any dependency has a license not in the allowlist. Dependencies with undetectable licenses are reported as `UNKNOWN`.

### Custom Configuration

Use an [osv-scanner config file](https://google.github.io/osv-scanner/configuration/) for advanced options like ignoring specific vulnerabilities or packages.

Config files are automatically discovered in these locations (no flag needed):
- `osv-scanner.toml` in the current directory
- `.osv-scanner.toml` in the current directory
- Parent directories (walking up)

```bash
# Automatic discovery - just add osv-scanner.toml to your repo
wraith scan go.mod

# Or specify a config file explicitly
wraith scan --config /path/to/custom-config.toml go.mod
```

Example `osv-scanner.toml`:
```toml
[[IgnoredVulns]]
id = "GO-2024-1234"
reason = "False positive - not exploitable in our usage"

[[PackageOverrides]]
name = "stdlib"
ecosystem = "Go"
ignore = true
reason = "Go stdlib license (BSD-3-Clause) not detected by osv-scanner"
```

### Exit Codes

- `0`: No vulnerabilities or license violations found
- `1`: Vulnerabilities found, license violations found, or error occurred

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

    // Scan with options
    result, err := scanner.ScanLockfile("poetry.lock",
        wraith.WithOffline(),                              // Use local DB only
        wraith.WithLicenseAllowlist("MIT", "Apache-2.0"),  // Check licenses
        wraith.WithConfigFile("osv-scanner.toml"),         // Custom config
    )
    if err != nil {
        log.Fatalf("Scan failed: %v", err)
    }

    // Process vulnerability results
    for _, pkg := range result.GetPackagesWithVulnerabilities() {
        fmt.Printf("Package: %s v%s (%s)\n",
            pkg.Package.Name,
            pkg.Package.Version,
            pkg.Package.Ecosystem)

        for _, vuln := range pkg.Vulnerabilities {
            fmt.Printf("  - %s: %s\n", vuln.ID, vuln.Summary)
        }
    }

    // Process license violations
    for _, pkg := range result.GetPackagesWithLicenseViolations() {
        fmt.Printf("License violation: %s v%s - %v\n",
            pkg.Package.Name,
            pkg.Package.Version,
            pkg.LicenseViolations)
    }
}
```

### Scan Options

| Option | Description |
|--------|-------------|
| `WithOffline()` | Scan using only the local vulnerability database |
| `WithOfflineDownload()` | Download/refresh the local database before scanning |
| `WithConfigFile(path)` | Use a custom osv-scanner config file |
| `WithLicenses()` | Enable license scanning (informational) |
| `WithLicenseAllowlist(licenses...)` | Enforce a license allowlist |

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
