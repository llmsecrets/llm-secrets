# LLM Secrets

**Protect your .env secrets from AI coding assistants.**

LLM Secrets encrypts your environment files with Windows Hello authentication. Claude Code can *use* your secrets without ever *seeing* them.

[![Windows 10/11](https://img.shields.io/badge/Windows-10%2F11-0078D6?logo=windows)](https://llmsecrets.com)
[![License: Apache 2.0](https://img.shields.io/badge/CLI-Apache%202.0-blue)](LICENSE-APACHE)
[![License: Source Available](https://img.shields.io/badge/Desktop-Source%20Available-green)](LICENSE)

## The Problem

When you use Claude Code, it reads your `.env` file. Your API keys, database passwords, and private keys are loaded into the AI's context window.

```
[!] Claude Code just read your .env:
    PRIVATE_KEY=0x7f3a8b2c...
    STRIPE_SECRET_KEY=sk_live_...
    DATABASE_URL=postgres://admin:password@...
```

## The Solution

LLM Secrets encrypts your `.env` with Windows Hello. At runtime, secrets are decrypted only in isolated subprocesses.

```
✓ Claude sees:     $env:PRIVATE_KEY
✗ Claude sees NOT: 0x7f3a8b2c9d4e5f6a...
```

## Quick Start

### CLI (Free, Apache 2.0)

```bash
# Install
npm install -g llm-secrets

# Encrypt existing .env
scrt setup

# View secrets (requires Windows Hello)
scrt view

# Use with any command
scrt run -- npm start
```

### Desktop App (Source Available)

Download from [llmsecrets.com](https://llmsecrets.com) or build from source.

## Licensing

| Component | License | You Can |
|-----------|---------|---------|
| **Crypto Core** | Apache 2.0 | Use, modify, sell, anything |
| **CLI Tool** | Apache 2.0 | Use, modify, sell, anything |
| **Desktop App** | Source Available | View, audit, build for personal use |

### Why This Model?

Security software should be auditable. You can read every line of cryptographic code to verify there are no backdoors. The paid desktop app license supports continued development.

**Building from source?** The LicenseService in this repo is a stub that accepts any valid-format key (e.g., `TEST-TEST-TEST-TEST`). Official builds use HMAC validation.

## Project Structure

```
llm-secrets/
├── crypto-core/          # Apache 2.0 - Encryption library
│   ├── EnvCrypto.psm1    # PowerShell encryption module
│   └── WindowsHelloAuth.cs
│
├── cli/                  # Apache 2.0 - Command line tool
│   ├── scrt.ps1
│   └── commands/
│
├── desktop-app/          # Source Available - Electron app
│   └── src/
│
└── disaster-recovery/    # Recovery scripts
```

## Security

- **AES-256-CBC** encryption for .env files
- **Windows Hello** authentication (TPM-backed)
- **DPAPI** protection for master keys
- Secrets decrypted only in **isolated subprocesses**
- Claude never sees decrypted values

## Building from Source

### Prerequisites
- Windows 10/11 with Windows Hello enabled
- Node.js 18+
- npm or Bun

### Build

```bash
cd desktop-app
npm install
npm run build
npm run package
```

### Development

```bash
npm run dev
```

## Documentation

- [Full Documentation](https://docs.llmsecrets.com)
- [Security Model](https://docs.llmsecrets.com#security-model)
- [CLI Commands](https://docs.llmsecrets.com#commands)

## Contributing

Contributions welcome for the Apache 2.0 components (crypto-core and CLI).

For the desktop app, please open an issue first to discuss changes.

## Support

- **Website**: [llmsecrets.com](https://llmsecrets.com)
- **Docs**: [docs.llmsecrets.com](https://docs.llmsecrets.com)
- **Issues**: [GitHub Issues](https://github.com/llmsecrets/llm-secrets/issues)

---

Made with care for developers who value their secrets.
