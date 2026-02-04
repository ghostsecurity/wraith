#!/bin/bash
set -e

OSV_VERSION="${OSV_VERSION:-v2.3.2}"
BUILD_DIR="build/osv-scanner"

echo "Downloading osv-scanner ${OSV_VERSION}..."

# Create platform-specific directories with simple binary names
mkdir -p "$BUILD_DIR/linux_amd64"
mkdir -p "$BUILD_DIR/linux_arm64"
mkdir -p "$BUILD_DIR/darwin_amd64"
mkdir -p "$BUILD_DIR/darwin_arm64"
mkdir -p "$BUILD_DIR/windows_amd64"

# Linux amd64
curl -L --fail --silent --show-error \
  "https://github.com/google/osv-scanner/releases/download/${OSV_VERSION}/osv-scanner_linux_amd64" \
  -o "$BUILD_DIR/linux_amd64/osv-scanner"
chmod +x "$BUILD_DIR/linux_amd64/osv-scanner"

# Linux arm64
curl -L --fail --silent --show-error \
  "https://github.com/google/osv-scanner/releases/download/${OSV_VERSION}/osv-scanner_linux_arm64" \
  -o "$BUILD_DIR/linux_arm64/osv-scanner"
chmod +x "$BUILD_DIR/linux_arm64/osv-scanner"

# Darwin amd64
curl -L --fail --silent --show-error \
  "https://github.com/google/osv-scanner/releases/download/${OSV_VERSION}/osv-scanner_darwin_amd64" \
  -o "$BUILD_DIR/darwin_amd64/osv-scanner"
chmod +x "$BUILD_DIR/darwin_amd64/osv-scanner"

# Darwin arm64
curl -L --fail --silent --show-error \
  "https://github.com/google/osv-scanner/releases/download/${OSV_VERSION}/osv-scanner_darwin_arm64" \
  -o "$BUILD_DIR/darwin_arm64/osv-scanner"
chmod +x "$BUILD_DIR/darwin_arm64/osv-scanner"

# Windows amd64
curl -L --fail --silent --show-error \
  "https://github.com/google/osv-scanner/releases/download/${OSV_VERSION}/osv-scanner_windows_amd64.exe" \
  -o "$BUILD_DIR/windows_amd64/osv-scanner.exe"

echo "Downloaded osv-scanner ${OSV_VERSION} for all platforms"
find "$BUILD_DIR" -type f
