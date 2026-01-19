# LLM Secrets Software License

**Copyright (C) 2025 LLM Secrets**

**Product Name:** LLM Secrets - Windows Hello Encryption System
**Website:** https://llmsecrets.com
**Repository:** https://github.com/llmsecrets/llm-secrets

---

## Dual License Structure

LLM Secrets uses a **dual-license model** to balance trust and sustainability:

| Component | License | You Can |
|-----------|---------|---------|
| **Encryption Core** | Apache 2.0 | Use, modify, sell, anything |
| **CLI Tool (`scrt`)** | Apache 2.0 | Use, modify, sell, anything |
| **Desktop App** | Source Available | View, audit, build for personal use |
| **Desktop App** | **Paid License** | Commercial use, official builds |

### Why This Model?

Security software should be auditable. You can read every line of cryptographic
code to verify there's no backdoors. The paid license for the desktop app
supports continued development.

---

## Apache 2.0 Components (Fully Open Source)

The following components are licensed under the **Apache License 2.0**:

- `crypto-core/` - EnvCrypto.psm1, WindowsHelloAuth.cs
- `cli/` - scrt CLI tool and all commands
- `npm-package/` - CLI distribution package

**You may:**
- Use for any purpose (personal, commercial)
- Modify and create derivative works
- Distribute and sublicense
- Use in proprietary software

**Requirements:**
- Include copyright notice and Apache 2.0 license
- State changes if you modify the code
- Include NOTICE file if present

See `LICENSE-APACHE` for full terms.

---

## Source Available Components (Desktop App)

The **Desktop Application** (desktop-app/) is licensed under a
**Source Available License** based on Elastic License 2.0.

**You may:**
- View and audit the source code for security
- Build from source for personal, non-commercial use
- Report security vulnerabilities
- Learn from the codebase

**You may NOT:**
- Redistribute the software without permission
- Sell or sublicense the software
- Remove or bypass the license key system
- Provide as a hosted/managed service
- Use LLM Secrets branding without permission

See `LICENSE` for full terms.

---

## Purchasing a License

To use LLM Secrets commercially or obtain redistribution rights:

**Website:** https://llmsecrets.com
**Email:** support@llmsecrets.com

A license includes:
- Official builds with automatic updates
- Commercial use rights
- Priority support

---

## Encryption Disclaimer

This software uses **AES-256 encryption** and **Windows Hello authentication**.

### No Warranty for Encryption

NO WARRANTY is provided that encryption will be unbreakable or that data
will be recoverable if:

- Master key is lost
- Windows Hello authentication fails
- Hardware or software failures occur

### User Responsibilities

You are solely responsible for:

1. **Backup Your Master Key** - Store in a password manager or secure location
2. **Test Recovery** - Verify you can decrypt before relying on the system
3. **Maintain Backups** - Keep backups of critical data

---

## Disclaimer of Warranty

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.

---

## Limitation of Liability

IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE.

### Data Loss Scenarios

The developers are NOT liable for data loss resulting from:
- Lost or forgotten master keys
- Windows Hello authentication failures
- Hardware or software failures
- User error or misconfiguration
- Third-party dependency failures

---

## Export Control Notice

This software contains encryption technology and may be subject to export
control laws including U.S. Export Administration Regulations (EAR).

You may not use this software if you are:
- Located in a country subject to U.S. trade sanctions
- Prohibited from receiving U.S. exports
- Planning prohibited end-uses

---

## Contact

**Website:** https://llmsecrets.com
**Support:** support@llmsecrets.com
**Security Issues:** security@llmsecrets.com
**GitHub:** https://github.com/llmsecrets/llm-secrets

---

**Last Updated:** January 2025
**License Version:** 2.0
