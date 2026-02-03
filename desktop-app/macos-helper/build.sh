#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/../resources/macos"

mkdir -p "$OUTPUT_DIR"

echo "Building TouchIDAuth..."
swiftc \
    -O \
    -framework LocalAuthentication \
    -framework Foundation \
    -o "$OUTPUT_DIR/TouchIDAuth" \
    "$SCRIPT_DIR/TouchIDAuth.swift"

chmod +x "$OUTPUT_DIR/TouchIDAuth"
echo "Built: $OUTPUT_DIR/TouchIDAuth"
