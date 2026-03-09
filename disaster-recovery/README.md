# LLM Secrets - Disaster Recovery

If you've lost access to the app but have your backup file and recovery password, you can still recover your secrets.

## What You Need

1. `encrypted-master-key-instructions.json` (v2.0) or `master-key.backup` (v1.0) — your encrypted backup file
2. Your **recovery password** — the password you set when creating the backup
3. `.env.encrypted.v*` — your encrypted secrets files (if you want to decrypt without the app)

## Step 1: Recover Your Master Key

### WSL / Linux (scrt2)

```bash
# If scrt2 is installed:
scrt2 recover encrypted-master-key-instructions.json

# Standalone (no scrt2 needed):
./recover-master-key.sh encrypted-master-key-instructions.json

# Also works with v1.0 backup files:
./recover-master-key.sh master-key.backup
```

### Windows (PowerShell)

```powershell
.\Decrypt-MasterKeyBackup.ps1 -BackupFile "master-key.backup"
```

This will prompt for your recovery password and output your 44-character master key.

## Step 2: Use the Master Key

### Option A: Import into scrt2

```bash
scrt2 migrate "your44charkey=="
```

### Option B: In the App (Windows)

1. Open LLM Secrets
2. Click "Decrypt"
3. Paste the master key
4. Click "Decrypt with Key"

### Option C: Decrypt .env.encrypted files directly

**WSL / Linux:**
```bash
./decrypt-env-file.sh -k "your44charkey==" -f .env.encrypted.v5
```

**Windows (PowerShell):**
```powershell
.\Decrypt-EnvFile.ps1 -MasterKey "your44charkey==" -EncryptedFile ".env.encrypted"
```

This decrypts your `.env.encrypted` file to `.env`.

## Creating a Backup (scrt2)

```bash
# Save encrypted master key backup (prompts for recovery password):
scrt2 backup-key --save ~/Desktop

# Creates: ~/Desktop/encrypted-master-key-instructions.json
# Store this file + your recovery password in separate secure locations.
```

## Security Notes

- Delete `.env` after extracting what you need — it contains plaintext secrets
- Never share your master key or recovery password
- Store the backup file and recovery password in **separate** secure locations
- WSL scripts require: python3, openssl, jq
- PowerShell scripts require: PowerShell 5.1+ (included in Windows 10/11)

## Technical Details

### Backup Encryption
- **Key Derivation:** PBKDF2-SHA256, 100,000 iterations
- **Encryption:** AES-256-CBC
- **Master Key:** 32 bytes (44 characters base64)

### Backup File Formats
- **v2.0** (`encrypted-master-key-instructions.json`): Created by scrt2, clean JSON
- **v1.0** (`master-key.backup`): Created by LLM Secrets Windows app, may have UTF-8 BOM

### .env.encrypted Format
- **Format:** JSON with `Data` field containing base64-encoded data
- **Data Structure:** IV (16 bytes) + AES-256-CBC ciphertext
- **Encryption:** AES-256-CBC with master key

### Vault Location
- **Windows:** `%APPDATA%\LLM Secrets 2\env\`
- **Files:** `.env.encrypted.v1` through `.env.encrypted.v5` (versioned)
- **DPAPI Key:** `%APPDATA%\LLM Secrets 2\credentials\EnvCrypto_DpapiMasterKey.dat`
