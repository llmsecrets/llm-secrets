# Building LLM Secrets from Source

This guide covers building the macOS desktop app from source. Building from source lets you verify that the published binary matches the open-source code.

## macOS v3.1.0

### Prerequisites

| Requirement | Minimum | How to install |
|-------------|---------|----------------|
| macOS | 12 (Monterey) | - |
| Node.js | 18+ | `brew install node` or [nodejs.org](https://nodejs.org) |
| npm | 9+ | Included with Node.js |
| Xcode CLT | 14+ | `xcode-select --install` |
| Touch ID | Required at runtime | Built-in on supported Macs |

### Build Steps

```bash
# 1. Clone the repo and check out the release tag
git clone https://github.com/llmsecrets/llm-secrets.git
cd llm-secrets
git checkout v3.1.0

# 2. Install dependencies
cd desktop-app
npm install

# 3. Build the Swift Touch ID helper (universal binary: arm64 + x86_64)
npm run build:touchid

# 4. Package the app
npm run make:mac
```

**Output:** `out/make/zip/darwin/arm64/LLM Secrets-darwin-arm64-*.zip`

The `.app` bundle is inside the zip. Extract and move to `/Applications`.

### Using Homebrew (coming soon)

```bash
brew tap llmsecrets/llm-secrets
brew install --cask llm-secrets
```

See [issue #3](https://github.com/llmsecrets/llm-secrets/issues/3) for status.

### Unsigned builds (no Apple Developer account)

Without `APPLE_ID` and `APPLE_TEAM_ID` environment variables, code signing and notarization are skipped automatically. macOS Gatekeeper will block the app on first launch.

**To open an unsigned build:**
1. Right-click the app in Finder
2. Click "Open"
3. Click "Open" again in the dialog

You only need to do this once. After that, the app opens normally.

**Note:** Without code signing, Secure Enclave is unavailable. The app automatically falls back to AES-GCM encryption with the master key stored in macOS Keychain. This is still secure — the only difference is the key is protected by Keychain access controls rather than the Secure Enclave hardware.

---

## Security Verification

Since Electron binaries are not reproducible (code signing, build timestamps, native module metadata), security verification is done through source code audit.

### Step 1: Verify the official download (optional)

If you downloaded the pre-built release instead of building from source:

```bash
sha256sum LLM-Secrets-macOS-v3.1.0.dmg
# Expected: dd1c6726ea159fba38c8cf78a22012709f06c69a7d29e19f33029b8b789f1550
```

### Step 2: Audit the security-critical files

There are only 4 files that handle authentication and encryption. The entire security surface is small enough to read in 10 minutes.

#### `macos-helper/TouchIDAuth.swift` (27 lines)

The Touch ID authentication binary. Verify:
- Uses `LAContext.evaluatePolicy(.deviceOwnerAuthentication)` — Touch ID with password fallback
- Returns exit code `0` (success), `1` (auth failed), or `2` (no auth available)
- No network calls, no file I/O, no data exfiltration
- Prompt text says "Unlock LLM Secrets vault" — nothing misleading

#### `src/main/services/AuthServiceMac.ts` (41 lines)

Spawns the Touch ID binary. Verify:
- Calls `execFile` with the `TouchIDAuth` binary path — no shell injection possible
- 30-second timeout on authentication
- Only checks the exit code — does not parse or transmit any data
- Binary path resolves to `resources/macos/TouchIDAuth` (bundled in the app)

#### `src/main/services/CryptoServiceMac.ts` (162 lines)

Handles all encryption. Verify:
- Master key: 32 random bytes, stored in macOS Keychain via `keytar` (service: `LLMSecrets`)
- Encryption: AES-256-CBC with PBKDF2 key derivation (100,000 iterations, SHA-256)
- Each encryption uses a fresh random salt (16 bytes) and IV (16 bytes)
- Encrypted files have `0o600` permissions (owner-only read/write)
- Session key lives in memory only, with expiry (default 2 hours)
- `listSecretNames()` returns key names only — never values
- `decryptEnv()` returns plaintext only to the Electron main process — verify it is never sent to the renderer via IPC

#### `entitlements.mac.plist` (39 lines)

macOS app entitlements. Verify these are expected and appropriately scoped:

| Entitlement | Purpose | Expected? |
|------------|---------|-----------|
| `biometric-authentication` | Touch ID | Yes |
| `keychain-access-groups` | Store master key | Yes |
| `network.client` | Check for updates | Yes |
| `files.user-selected.read-write` | Read/write .env files | Yes |
| `allow-jit` | Electron runtime requirement | Yes |
| `allow-unsigned-executable-memory` | Electron runtime requirement | Yes |
| `disable-library-validation` | Electron runtime requirement | Yes |
| `disable-executable-page-protection` | Electron runtime requirement | Yes |

The last four are standard Electron hardened runtime exceptions. Without them, the app would crash on launch.

### Step 3: Verify no secrets leak to the LLM

The core security guarantee: secret values are injected as environment variables into isolated subprocesses and never returned to Claude Code or any LLM.

```bash
# From the desktop-app directory, search for any code that might return secret values
grep -rn "secret.*value\|plaintext\|decrypt.*return" src/main/services/

# Verify decryptEnv is only called internally, not exposed via IPC to renderer
grep -rn "decryptEnv\|plaintext" src/main/ src/preload.ts
```

`decryptEnv()` should only be called by `listSecretNames()` (which strips values) and the subprocess injection path (which passes values to `child_process.exec` environment, not back to the renderer).

### Step 4: Verify Electron Fuses

The `forge.config.ts` sets these security fuses at package time:

| Fuse | Setting | Effect |
|------|---------|--------|
| `RunAsNode` | Disabled | Prevents using the app as a Node.js runtime |
| `EnableCookieEncryption` | Enabled | Encrypts cookies on disk |
| `EnableNodeOptionsEnvironmentVariable` | Disabled | Blocks NODE_OPTIONS injection |
| `EnableNodeCliInspectArguments` | Disabled | Blocks --inspect debugging |
| `EnableEmbeddedAsarIntegrityValidation` | Enabled | Validates asar archive integrity |
| `OnlyLoadAppFromAsar` | Enabled | Prevents loading unpacked app code |

---

## Why Binaries Are Not Reproducible

Electron apps cannot produce identical binaries across builds because:

1. **Code signing** — Apple Developer certificates embed unique identifiers
2. **Notarization** — Apple's notarization service adds unique stapled tickets
3. **Build timestamps** — Webpack embeds timestamps in bundles
4. **Native modules** — `keytar` is compiled per-platform with different build metadata

This is why source code audit is the recommended verification method.

---

## Security Contact

Report security issues to: josh@lendvest.io
