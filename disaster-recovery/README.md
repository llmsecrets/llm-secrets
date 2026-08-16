# scrt4 — Disaster Recovery

If you have lost access to your authenticator, your machine, or the scrt4
binaries, this directory recovers your vault **without the app**.

The scripts here are deliberately standalone. They depend only on `openssl`
(Unix) or .NET (Windows), both of which ship with the OS or with any normal
developer install. You do not need scrt4, a daemon, a network connection, or
your authenticator to run them.

> **Recovering the old LLM Secrets desktop app instead?** That product used a
> different format (`.env.encrypted`, a 44-character master key, and
> `master-key.backup`). Its recovery scripts are preserved in the
> `archive/legacy-stack` branch. They do not work on a scrt4 vault, and the
> scripts here do not work on a v1/v3 backup.

---

## What you need

Recovery needs **two** things. Losing either one is unrecoverable — there is no
server-side reset, because there is no server-side anything.

| | What it is | Where it came from |
|---|---|---|
| **The backup file** | `encrypted-master-key-instructions.json` | `scrt4 backup-key --save <dir>` |
| **The recovery password** | The password you typed when creating that backup | Your memory, or your password manager |

Your encrypted vault (`~/.scrt4/` on Unix, `%USERPROFILE%\.scrt4\` on Windows)
is useful but not required for the recovery step itself — the master key
recovered here is what decrypts it.

### If you do not have a backup file

Make one now, while you still can:

```
scrt4 unlock
scrt4 backup-key --save ~/Desktop
```

Store the resulting JSON somewhere your authenticator is not. A USB key in a
drawer, or your password manager's secure-file attachment. Not the same laptop.

---

## The backup format

Documented here so the file is recoverable by hand in fifty years with nothing
but a crypto library, which is the point of writing it down.

```jsonc
{
  "Version": "1.0",
  "CreatedAt": "2026-08-16T10:00:00Z",
  "Salt":               "<base64, 16 bytes>",
  "IV":                 "<base64, 16 bytes>",
  "EncryptedMasterKey": "<base64 ciphertext>",
  "DecryptionInstructions": {
    "KeyDerivation": "PBKDF2-SHA256",
    "Iterations": 100000
  }
}
```

- **Key derivation** — PBKDF2-HMAC-SHA256 over your recovery password, with the
  stored `Salt`, `Iterations` (default 100,000), producing a 32-byte key.
- **Cipher** — AES-256-CBC with PKCS#7 padding and the stored `IV`.
- **No OpenSSL `Salted__` header.** The salt lives in the JSON, not in the
  ciphertext. If you decrypt by hand you must pass `-nosalt` and supply `-K`
  and `-iv` explicitly. This is the single most common way a manual recovery
  attempt fails.

The bash and PowerShell clients write byte-identical files, so a backup taken
on Windows recovers on Linux and vice versa.

---

## Recovering

### Unix, macOS, WSL

```bash
./recover-master-key.sh encrypted-master-key-instructions.json
```

### Windows

```powershell
.\Recover-MasterKey.ps1 -BackupFile .\encrypted-master-key-instructions.json
```

Both prompt for the recovery password and print the recovered master key. Both
refuse to write the key to disk — copy it straight into the target machine.

### Then restore the vault

On the machine you are recovering onto:

```
scrt4 setup            # enroll a new authenticator
scrt4 restore-key      # paste the recovered master key
```

Your existing `~/.scrt4/vault.enc` is decrypted with the restored key and
re-sealed under the new authenticator's derived key. If you do not have the
vault file, you have the key but nothing to open — which is why a vault backup
is worth keeping alongside the key backup.

---

## Threat notes

- **The recovered key is the whole vault.** Treat the terminal it prints in as
  compromised afterwards. Clear scrollback.
- **The backup file alone is not enough**, and neither is the password alone.
  That is deliberate: it means the file is safe to store somewhere merely
  private rather than somewhere perfectly secure.
- **100,000 PBKDF2 iterations is the 2026 floor, not a ceiling.** A short or
  reused recovery password is the weak link in this design. Use a long one.

---

## Testing your backup

Do this once, now, rather than discovering a problem during an actual disaster:

```bash
./recover-master-key.sh encrypted-master-key-instructions.json
# compare the printed key against:
scrt4 unlock && scrt4 backup-key
```

The two must match exactly. If they do not, the backup is stale — take a
new one.
