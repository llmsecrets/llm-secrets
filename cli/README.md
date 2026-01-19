# LLM Secrets CLI

**License: Apache 2.0**

Command-line tool for managing encrypted secrets with Windows Hello authentication.

## Installation

```bash
npm install -g llm-secrets
```

Or use directly with PowerShell:

```powershell
# Add to your PowerShell profile
Import-Module "path\to\cli\ScrtCli.psm1"
```

## Commands

| Command | Description |
|---------|-------------|
| `scrt setup [path]` | First-time setup: encrypt existing .env file |
| `scrt view [name]` | Authenticate + view secrets |
| `scrt auth` | Start Windows Hello session |
| `scrt status` | Show session status |
| `scrt logout` | End session |
| `scrt encrypt` | Encrypt .env to .env.encrypted |
| `scrt decrypt` | Decrypt .env.encrypted to .env |
| `scrt list` | List secret names (never values) |
| `scrt run -- cmd` | Run command with secrets injected |
| `scrt help [cmd]` | Show help |

## Quick Start

```bash
# Encrypt your existing .env file
scrt setup

# View your secrets (requires Windows Hello)
scrt view

# Run a command with secrets injected
scrt run -- npm start

# Deploy with private key (Claude never sees it)
scrt run -- forge script Deploy.s.sol --private-key $env:PRIVATE_KEY
```

## How It Works

1. **Setup**: Encrypts your .env with AES-256, protected by Windows Hello
2. **Authentication**: Uses Windows Hello biometrics to unlock secrets
3. **Injection**: Secrets are decrypted only in isolated subprocesses
4. **Security**: Claude Code sees `$env:SECRET_NAME`, never the actual value

## File Structure

```
cli/
├── scrt.ps1           # Main entry point
├── ScrtCli.psm1       # PowerShell module
├── commands/
│   ├── Auth.ps1       # Windows Hello authentication
│   ├── Decrypt.ps1    # Decrypt .env.encrypted
│   ├── Encrypt.ps1    # Encrypt .env
│   ├── Help.ps1       # Help system
│   ├── Init.ps1       # Initialize new vault
│   ├── List.ps1       # List secret names
│   ├── Logout.ps1     # End session
│   ├── Run.ps1        # Run with secrets
│   ├── Setup.ps1      # First-time setup wizard
│   ├── Status.ps1     # Session status
│   ├── Version.ps1    # Version info
│   └── View.ps1       # View secrets
└── lib/
    ├── Logging.ps1    # Audit logging
    └── Output.ps1     # Console formatting
```

## License

```
SPDX-License-Identifier: Apache-2.0
```

This is fully open source software. You may use, modify, and distribute it freely.
