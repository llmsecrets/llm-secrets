# Build Verification

This document provides SHA256 checksums and verification status for all official releases.

## Current Releases

| Platform | Version | SHA256 | Verification |
|----------|---------|--------|--------------|
| **Windows** | 3.0.20 | `6f22b341229f37a0bd95eb948696468b15fdce1035e548ea4c150f3b32b19913` | Source Verified |
| **macOS** | 3.1.0 | `710cf88233d3856fb415e5bfab1df7ce263af8ad6a6b1b88b11e8bda7d2d2272` | Source Available |
| **WSL/Linux** | 0.3.0 | `fe572ef7b300412255040cda6576e5f518289c41b405f41077173cdf430bed95` | Reproducible Build |

## Download URLs

- **Windows:** https://sign.lendvest.io/downloads/LLM-Secrets-3.0.20-Setup.exe
- **macOS:** https://sign.lendvest.io/downloads/LLM-Secrets-3.1.0-macOS-arm64.zip
- **WSL/Linux:** https://sign.lendvest.io/downloads/scrt-wsl-0.3.0.tar.gz

## Verification Commands

```bash
# Windows (PowerShell)
(Get-FileHash .\LLM-Secrets-3.0.20-Setup.exe -Algorithm SHA256).Hash

# macOS/Linux
sha256sum LLM-Secrets-3.1.0-macOS-arm64.zip
sha256sum scrt-wsl-0.3.0.tar.gz
```

---

## WSL/Linux v0.3.0 — Reproducible Build ✅

**Status:** Fully reproducible. Building from source produces identical binary.

### Binary Verification

| Component | SHA256 |
|-----------|--------|
| `scrt-daemon` binary | `bba00a725de086b42a8a9ae50ae15a5be1f078d725d5cf0bfca447bf4e2b4bb4` |
| Release tarball | `fe572ef7b300412255040cda6576e5f518289c41b405f41077173cdf430bed95` |

### Source File Verification

All source files in `wsl-daemon/src/` match the release tarball exactly:

| File | Status |
|------|--------|
| main.rs | ✅ MATCH |
| audit.rs | ✅ MATCH |
| dpapi.rs | ✅ MATCH |
| handlers.rs | ✅ MATCH |
| protocol.rs | ✅ MATCH |
| remote.rs | ✅ MATCH |
| sanitize.rs | ✅ MATCH |
| session.rs | ✅ MATCH |
| subprocess.rs | ✅ MATCH |
| scrt-client/src/main.rs | ✅ MATCH |

### Reproduce the Build

```bash
cd wsl-daemon
cargo build --release

# Verify binary hash
sha256sum target/release/scrt-daemon
# Expected: bba00a725de086b42a8a9ae50ae15a5be1f078d725d5cf0bfca447bf4e2b4bb4
```

---

## Windows v3.0.20 — Source Verified ✅

**Status:** Source code verified. Binary not reproducible due to code signing and build timestamps.

### Installer Verification

| Component | SHA256 |
|-----------|--------|
| LLM-Secrets-3.0.20-Setup.exe | `6f22b341229f37a0bd95eb948696468b15fdce1035e548ea4c150f3b32b19913` |

### Source File Verification

All TypeScript source files in `desktop-app/src/` match the build source:

| File | Status |
|------|--------|
| index.ts | ✅ MATCH |
| preload.ts | ✅ MATCH |
| renderer.tsx | ✅ MATCH |
| main/services/CryptoService.ts | ✅ MATCH |
| main/services/AuthService.ts | ✅ MATCH |
| main/services/LicenseService.ts | ✅ MATCH |
| main/services/BackupRestoreService.ts | ✅ MATCH |
| main/services/AutoLockService.ts | ✅ MATCH |
| main/services/UserActivityLogger.ts | ✅ MATCH |
| main/services/WalletService.ts | ✅ MATCH |
| main/services/CryptoServiceMac.ts | ✅ MATCH |
| main/services/CryptoServiceWsl.ts | ✅ MATCH |
| main/services/AuthServiceMac.ts | ✅ MATCH |
| renderer/App.tsx | ✅ MATCH |
| renderer/components/About.tsx | ✅ MATCH |
| renderer/components/Backup.tsx | ✅ MATCH |
| renderer/components/ClaudeMd.tsx | ✅ MATCH |
| renderer/components/SecretManager.tsx | ✅ MATCH |
| renderer/components/Settings.tsx | ✅ MATCH |
| renderer/components/SetupWizard.tsx | ✅ MATCH |
| renderer/components/TransactionConfirm.tsx | ✅ MATCH |
| renderer/components/WalletTools.tsx | ✅ MATCH |

### Why Binary is Not Reproducible

Electron apps cannot produce identical binaries across builds because:
1. **Code signing** — Windows binaries are signed with certificates
2. **Build timestamps** — Webpack embeds timestamps in bundles
3. **Native modules** — `keytar` is compiled per-platform with different metadata

Users can audit the source code to verify the security implementation.

---

## macOS v3.1.0 — Source Available

**Status:** Source code available for audit. Binary not reproducible due to code signing.

### Installer Verification

| Component | SHA256 |
|-----------|--------|
| LLM-Secrets-3.1.0-macOS-arm64.zip | `710cf88233d3856fb415e5bfab1df7ce263af8ad6a6b1b88b11e8bda7d2d2272` |

### Source Location

- **Touch ID Helper:** `desktop-app/macos-helper/TouchIDAuth.swift`
- **Secure Enclave Integration:** `desktop-app/src/main/services/CryptoServiceMac.ts`
- **macOS Auth Service:** `desktop-app/src/main/services/AuthServiceMac.ts`

### Security Architecture

- Touch ID authentication via LocalAuthentication framework
- Secure Enclave for master key encryption (with dev mode fallback)
- XPC session daemon for secure key caching

### Why Binary is Not Reproducible

macOS apps cannot produce identical binaries because:
1. **Code signing** — Apps are signed with Apple Developer certificates
2. **Notarization** — Apple notarization adds unique identifiers
3. **Build timestamps** — Xcode embeds timestamps in binaries

---

## Verification History

| Date | Platform | Version | Verified By |
|------|----------|---------|-------------|
| 2026-02-03 | WSL/Linux | 0.3.0 | Reproducible build confirmed |
| 2026-02-03 | Windows | 3.0.20 | Source code verification |
| 2026-02-03 | macOS | 3.1.0 | Source available for audit |

---

## Security Contact

Report security issues to: josh@lendvest.io
