# Crypto Core

**License: Apache 2.0**

This is the cryptographic core of LLM Secrets. It handles all encryption, decryption, and Windows Hello authentication.

## Files

| File | Description |
|------|-------------|
| `EnvCrypto.psm1` | PowerShell module for AES-256-CBC encryption/decryption |
| `WindowsHelloAuth.cs` | C# Windows Hello + DPAPI authentication |

## Security

- **AES-256-CBC** encryption with random IV per operation
- **PBKDF2-SHA256** key derivation (100,000 iterations for backups)
- **Windows DPAPI** protection for master keys
- **Windows Hello** biometric authentication

## Usage

```powershell
# Import the module
Import-Module .\EnvCrypto.psm1

# Encrypt a file
Protect-EnvFile -InputPath ".env" -OutputPath ".env.encrypted"

# Decrypt a file
Unprotect-EnvFile -InputPath ".env.encrypted" -OutputPath ".env"

# Decrypt to memory (never touches disk)
$secrets = Unprotect-EnvFile -InputPath ".env.encrypted" -InMemory
```

## Integration

This module is used by:
- The `scrt` CLI tool
- The LLM Secrets desktop app
- Disaster recovery scripts

## Building WindowsHelloAuth.exe

```bash
# Requires .NET SDK
dotnet build WindowsHelloAuth.csproj
```

## License

```
SPDX-License-Identifier: Apache-2.0
```

This is fully open source software. You may use, modify, and distribute it freely, including in commercial products.
