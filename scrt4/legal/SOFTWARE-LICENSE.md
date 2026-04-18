# LLM Secrets Software License

**Copyright (C) 2025-2026 LLM Secrets**

**Product Name:** LLM Secrets - Windows Hello Encryption System
**Website:** https://llmsecrets.com
**Repository:** https://github.com/llmsecrets/llm-secrets

---

## License

LLM Secrets is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

This applies to ALL components:
- Encryption Core (`crypto-core/`)
- CLI Tool (`scrt`, `cli/`)
- Desktop Application (`desktop-app/`)
- WSL2 Daemon (`wsl2-daemon/`)
- NPM Package (`npm-package/`)

### You May:
- Use for any purpose (personal, commercial)
- Modify and create derivative works
- Distribute copies
- Access and audit all source code

### Requirements:
- Include copyright notice and AGPL-3.0 license
- Disclose source code of modifications
- State changes if you modify the code
- **Network use clause:** If you run a modified version as a network service, you must make the source code available to users of that service

See `LICENSE` in the repository root for full AGPL-3.0 terms.

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

**Last Updated:** February 2026
**License Version:** 3.0 (AGPL-3.0)
