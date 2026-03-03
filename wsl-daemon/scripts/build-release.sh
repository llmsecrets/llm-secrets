#!/bin/bash
# Build a release tarball for scrt WSL daemon
# Produces: scrt-wsl-VERSION.tar.gz ready for GitHub release
#
# Usage: ./scripts/build-release.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/.."

VERSION=$(grep '^VERSION' "$PROJECT_DIR/Makefile" | head -1 | awk -F':=' '{print $2}' | tr -d ' ')
if [ -z "$VERSION" ]; then
    echo "ERROR: Could not read VERSION from Makefile"
    exit 1
fi

RELEASE_NAME="scrt-wsl-${VERSION}"
STAGING_DIR="/tmp/${RELEASE_NAME}"

echo "Building scrt WSL daemon v${VERSION}..."
echo ""

# Build
echo "==> Building daemon..."
(cd "$PROJECT_DIR" && cargo build --release)

echo "==> Building client..."
(cd "$PROJECT_DIR/scrt-client" && cargo build --release)

# Stage release
echo "==> Staging release..."
rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR/bin"
mkdir -p "$STAGING_DIR/install/completions"
mkdir -p "$STAGING_DIR/src"

# Binaries
cp "$PROJECT_DIR/target/release/scrt-daemon" "$STAGING_DIR/bin/"
cp "$PROJECT_DIR/scrt-client/target/release/scrt-client" "$STAGING_DIR/bin/"
cp "$PROJECT_DIR/bin/scrt" "$STAGING_DIR/bin/"

# Ensure LF line endings on shell scripts
sed -i 's/\r$//' "$STAGING_DIR/bin/scrt"

# Install files
cp "$PROJECT_DIR/install/install.sh" "$STAGING_DIR/install/"
cp "$PROJECT_DIR/install/uninstall.sh" "$STAGING_DIR/install/"
cp "$PROJECT_DIR/install/scrt-daemon.service" "$STAGING_DIR/install/"
cp "$PROJECT_DIR/install/scrt.1" "$STAGING_DIR/install/"
cp "$PROJECT_DIR/install/completions/scrt.bash" "$STAGING_DIR/install/completions/"
cp "$PROJECT_DIR/install/completions/_scrt" "$STAGING_DIR/install/completions/"

sed -i 's/\r$//' "$STAGING_DIR/install/install.sh"
sed -i 's/\r$//' "$STAGING_DIR/install/uninstall.sh"

# Docs
cp "$PROJECT_DIR/README.md" "$STAGING_DIR/"

# Source (for auditability)
cp -r "$PROJECT_DIR/src" "$STAGING_DIR/src/"
cp "$PROJECT_DIR/Cargo.toml" "$STAGING_DIR/"
cp "$PROJECT_DIR/Cargo.lock" "$STAGING_DIR/" 2>/dev/null || true
cp "$PROJECT_DIR/Makefile" "$STAGING_DIR/"

# Package
echo "==> Packaging tarball..."
TARBALL="${PROJECT_DIR}/${RELEASE_NAME}.tar.gz"
(cd /tmp && tar czf "$TARBALL" "$RELEASE_NAME")

# Checksums
echo "==> Generating checksums..."
sha256sum "$TARBALL" > "${TARBALL}.sha256"

# Cleanup staging
rm -rf "$STAGING_DIR"

echo ""
echo "Release built successfully!"
echo ""
echo "  Tarball:  $TARBALL"
echo "  Checksum: ${TARBALL}.sha256"
echo "  Size:     $(du -h "$TARBALL" | cut -f1)"
echo ""
echo "To install from tarball:"
echo "  tar xzf ${RELEASE_NAME}.tar.gz"
echo "  cd ${RELEASE_NAME}"
echo "  ./install/install.sh"
