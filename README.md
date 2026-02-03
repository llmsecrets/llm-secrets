# LLM Secrets

**Protect your .env secrets from AI coding assistants.**

LLM Secrets encrypts your environment files with biometric authentication (Windows Hello / Touch ID). Claude Code can *use* your secrets without ever *seeing* them.

[![Windows 10/11](https://img.shields.io/badge/Windows-10%2F11-0078D6?logo=windows)](https://llmsecrets.com/downloads)
[![macOS](https://img.shields.io/badge/macOS-Apple%20Silicon-000000?logo=apple)](https://llmsecrets.com/downloads)
[![WSL/Linux](https://img.shields.io/badge/WSL-Linux-FCC624?logo=linux)](https://llmsecrets.com/downloads)
[![License: Source Available](https://img.shields.io/badge/License-Source%20Available-green)](LICENSE)

## The Problem

When you use Claude Code, it reads your `.env` file. Your API keys, database passwords, and private keys are loaded into the AI's context window.

```
[!] Claude Code just read your .env:
    PRIVATE_KEY=0x7f3a8b2c...
    STRIPE_SECRET_KEY=sk_live_...
    DATABASE_URL=postgres://admin:password@...
```

## The Solution

LLM Secrets encrypts your `.env` with biometric authentication. At runtime, secrets are decrypted only in isolated subprocesses.

```
✓ Claude sees:     $env:PRIVATE_KEY
✗ Claude sees NOT: 0x7f3a8b2c9d4e5f6a...
```

## Downloads

| Platform | Version | Download | SHA256 |
|----------|---------|----------|--------|
| **Windows** | 3.0.20 | [LLM-Secrets-3.0.20-Setup.exe](https://sign.lendvest.io/downloads/LLM-Secrets-3.0.20-Setup.exe) | `6f22b341229f37a0bd95eb948696468b15fdce1035e548ea4c150f3b32b19913` |
| **macOS** (Apple Silicon) | 3.1.0 | [LLM-Secrets-3.1.0-macOS-arm64.zip](https://sign.lendvest.io/downloads/LLM-Secrets-3.1.0-macOS-arm64.zip) | `710cf88233d3856fb415e5bfab1df7ce263af8ad6a6b1b88b11e8bda7d2d2272` |
| **WSL/Linux** | 0.3.0 | [scrt-wsl-0.3.0.tar.gz](https://sign.lendvest.io/downloads/scrt-wsl-0.3.0.tar.gz) | `fe572ef7b300412255040cda6576e5f518289c41b405f41077173cdf430bed95` |

### Verify Your Download

```bash
# Windows (PowerShell)
(Get-FileHash .\LLM-Secrets-3.0.20-Setup.exe -Algorithm SHA256).Hash

# macOS/Linux
sha256sum LLM-Secrets-3.1.0-macOS-arm64.zip
sha256sum scrt-wsl-0.3.0.tar.gz
```

### System Requirements

| Platform | Requirements |
|----------|--------------|
| Windows | Windows 10/11 64-bit with Windows Hello configured |
| macOS | Apple Silicon (M1/M2/M3) with Touch ID |
| WSL/Linux | WSL2 on Windows (bridges to Windows Hello) |

## Quick Start

### Windows

1. Download and run the installer
2. Launch LLM Secrets
3. Authenticate with Windows Hello
4. Import your existing `.env` file

### macOS

1. Download and unzip
2. Move `LLM Secrets.app` to Applications
3. Launch and authenticate with Touch ID
4. Import your existing `.env` file

### WSL/Linux

```bash
# Download and extract
curl -LO https://sign.lendvest.io/downloads/scrt-wsl-0.3.0.tar.gz
tar xzf scrt-wsl-0.3.0.tar.gz
cd scrt-wsl-0.3.0

# Install
./install/install.sh

# Use (authenticates via Windows Hello)
scrt setup
scrt view
scrt run -- npm start
```

## Licensing

| Component | License | You Can |
|-----------|---------|---------|
| **Desktop Apps** | Source Available | View, audit, build for personal use |
| **WSL Daemon** | Source Available | View, audit, build for personal use |

### Why This Model?

Security software should be auditable. You can read every line of cryptographic code to verify there are no backdoors. The paid desktop app license supports continued development.

**Building from source?** The LicenseService in this repo is a stub that accepts any valid-format key (e.g., `TEST-TEST-TEST-TEST`). Official builds use HMAC validation.

## Project Structure

```
llm-secrets/
├── desktop-app/          # Source Available - Electron app (Windows/macOS)
│   ├── src/
│   ├── macos-helper/     # Touch ID + Secure Enclave (macOS)
│   └── resources/
│
├── wsl-daemon/           # Source Available - Rust daemon (WSL/Linux)
│   └── src/
│
├── docs/                 # Documentation (docs.llmsecrets.com)
│
└── disaster-recovery/    # Recovery scripts
```

## Security

### Windows
- **AES-256-CBC** encryption for .env files
- **Windows Hello** authentication (TPM-backed)
- **DPAPI** protection for master keys
- Secrets decrypted only in **isolated subprocesses**

### macOS
- **AES-256-GCM** encryption for .env files
- **Touch ID** authentication via LocalAuthentication framework
- **Secure Enclave** protection for master keys (with dev mode fallback)
- **XPC session daemon** for secure key caching

### WSL/Linux
- **Rust daemon** bridging to Windows Hello
- **Socket-based IPC** for secret requests
- **Session management** with timeouts
- **Audit logging** for all secret access

### Security FAQ

> *The following answers are from [DeepWiki](https://deepwiki.com/llmsecrets/llm-secrets), an independent third-party AI analysis of this codebase. Use their chatbot to ask your own security questions.*

<details>
<summary><strong>Can LLM Secrets, the developers, or Claude ever see my decrypted secrets?</strong></summary>

**No.** Here's why:

- **Client-side only** - All encryption/decryption happens locally on your machine. There is no server component.
- **Isolated subprocesses** - Secrets are decrypted only in isolated subprocesses. Claude sees `$env:SECRET_NAME`, never the actual value.
- **Hardware-backed keys** - Master keys are protected by TPM (Windows), Secure Enclave (macOS), or DPAPI.
- **In-memory only** - Decryption happens in memory, never writing plaintext to disk.
- **Fully auditable** - All source code is available. Verify yourself.

Even if the developers wanted to see your secrets (which they can't), the architecture makes it impossible since all operations are local and keys never leave your machine.

</details>

<details>
<summary><strong>What happens if I lose my device or master key?</strong></summary>

**You can recover IF you set up backups beforehand.**

**Recovery options:**
1. **Master Key Backup** - During setup, a 44-character key is shown once. Save it in your password manager.
2. **Recovery Password** - Set a recovery password that encrypts your master key for cloud backup.
3. **Disaster Recovery Scripts** - Work without the app installed.

**Without backups:** Your secrets are **irrecoverable by design**. There is no backdoor.

```
Lost Device/Master Key
         ├── Have saved master key? → Disaster recovery → ✓ Recovered
         ├── Have recovery password? → Decrypt backup → ✓ Recovered
         └── No backup? → ❌ Irrecoverable
```

</details>

## Building from Source

### Windows

```bash
cd desktop-app
npm install
npm run build
npm run package
```

### macOS

```bash
cd desktop-app
npm install
# Compile Swift helpers (requires Xcode)
./macos-helper/build.sh
npm run make -- --platform darwin
```

### WSL/Linux

```bash
cd wsl-daemon
cargo build --release
```

## Documentation

- [Full Documentation](https://docs.llmsecrets.com)
- [DeepWiki](https://deepwiki.com/llmsecrets/llm-secrets) - Third-party security analysis
- [Downloads](https://llmsecrets.com/downloads)

## Contributing

Contributions welcome for:
- **Bug fixes** - Security issues, crashes, edge cases
- **Documentation** (`docs/`) - Typos, clarifications, new guides

For new features, please open an issue first to discuss changes.

## Support

- **Website**: [llmsecrets.com](https://llmsecrets.com)
- **Downloads**: [llmsecrets.com/downloads](https://llmsecrets.com/downloads)
- **Docs**: [docs.llmsecrets.com](https://docs.llmsecrets.com)
- **Issues**: [GitHub Issues](https://github.com/llmsecrets/llm-secrets/issues)

## Acknowledgments

This project was inspired by [psst](https://github.com/Michaelliv/psst) by Michael Livshiz - a tool for protecting secrets from LLM context. We built upon this concept to create a biometric-integrated solution for AI coding assistants.

---

Made with care for developers who value their secrets.
