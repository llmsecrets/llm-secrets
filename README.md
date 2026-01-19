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

### Security FAQ

> *The following answers are from [DeepWiki](https://deepwiki.com/llmsecrets/llm-secrets), an independent third-party AI analysis of this codebase. Use their chatbot to ask your own security questions.*

<details>
<summary><strong>Can LLM Secrets, the developers, or Claude ever see my decrypted secrets?</strong></summary>

**No.** Here's why:

- **Client-side only** - All encryption/decryption happens locally on your machine. There is no server component.
- **Isolated subprocesses** - Secrets are decrypted only in isolated subprocesses. Claude sees `$env:SECRET_NAME`, never the actual value.
- **DPAPI protection** - Master keys are encrypted with Windows DPAPI, bound to your Windows user account and machine.
- **In-memory only** - Commands like `scrt view` decrypt to memory, never writing plaintext to disk.
- **Fully auditable** - The crypto core is Apache 2.0 open source. The desktop app is source available. Verify yourself.

Even if the developers wanted to see your secrets (which they can't), the architecture makes it impossible since all operations are local and keys never leave your machine.

</details>

<details>
<summary><strong>What happens if I lose my Windows account or master key?</strong></summary>

**You can recover IF you set up backups beforehand.**

**Recovery options:**
1. **Master Key Backup** - During setup, a 44-character key is shown once. Save it in your password manager.
2. **Recovery Password** - Set a recovery password that encrypts your master key for cloud backup.
3. **Disaster Recovery Scripts** - `Decrypt-MasterKeyBackup.ps1` and `Decrypt-EnvFile.ps1` work without the app installed.

**Without backups:** Your secrets are **irrecoverable by design**. There is no backdoor.

```
Lost Windows Account/Master Key
         ├── Have saved master key? → scrt decrypt --master-key → ✓ Recovered
         ├── Have recovery password? → Decrypt-MasterKeyBackup.ps1 → ✓ Recovered
         └── No backup? → ❌ Irrecoverable
```

**Action items:**
1. Save your 44-character master key from setup
2. Set up a recovery password in the desktop app
3. Test recovery before relying on the system

</details>

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
- [DeepWiki](https://deepwiki.com/llmsecrets/llm-secrets) - Use this free resource and its chatbot for third-party security analysis and to help validate trust in this repo
- [Security Model](https://docs.llmsecrets.com#security-model)
- [CLI Commands](https://docs.llmsecrets.com#commands)

## Contributing

Contributions welcome for the Apache 2.0 components (crypto-core and CLI).

For the desktop app, please open an issue first to discuss changes.

## Support

- **Website**: [llmsecrets.com](https://llmsecrets.com)
- **Docs**: [docs.llmsecrets.com](https://docs.llmsecrets.com)
- **Issues**: [GitHub Issues](https://github.com/llmsecrets/llm-secrets/issues)

## Acknowledgments

This project was inspired by [psst](https://github.com/Michaelliv/psst) by Michael Livshiz - a tool for protecting secrets from LLM context. We built upon this concept to create a Windows Hello-integrated solution for AI coding assistants.

---

Made with care for developers who value their secrets.
