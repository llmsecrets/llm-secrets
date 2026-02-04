#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/../resources/macos"

mkdir -p "$OUTPUT_DIR"

echo "Building TouchIDAuth (universal binary for arm64 + x86_64)..."

# Build for ARM64 (Apple Silicon)
swiftc \
    -O \
    -framework LocalAuthentication \
    -framework Foundation \
    -target arm64-apple-macosx11.0 \
    -o "$OUTPUT_DIR/TouchIDAuth-arm64" \
    "$SCRIPT_DIR/TouchIDAuth.swift"

# Build for x86_64 (Intel)
swiftc \
    -O \
    -framework LocalAuthentication \
    -framework Foundation \
    -target x86_64-apple-macosx11.0 \
    -o "$OUTPUT_DIR/TouchIDAuth-x86_64" \
    "$SCRIPT_DIR/TouchIDAuth.swift"

# Create universal binary
lipo -create \
    -output "$OUTPUT_DIR/TouchIDAuth" \
    "$OUTPUT_DIR/TouchIDAuth-arm64" \
    "$OUTPUT_DIR/TouchIDAuth-x86_64"

# Clean up architecture-specific binaries
rm "$OUTPUT_DIR/TouchIDAuth-arm64" "$OUTPUT_DIR/TouchIDAuth-x86_64"

chmod +x "$OUTPUT_DIR/TouchIDAuth"
echo "Built universal binary: $OUTPUT_DIR/TouchIDAuth"
file "$OUTPUT_DIR/TouchIDAuth"
