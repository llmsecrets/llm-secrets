# Simple Secret - Disaster Recovery

If you've lost access to the Simple Secret app but have your backup file and recovery password, you can still recover your secrets.

## What You Need

1. `master-key.backup` - The backup file you uploaded to Google Drive
2. Your **recovery password** - The password you set when creating the backup
3. `.env.encrypted` - Your encrypted secrets file (if you want to decrypt without the app)

## Step 1: Recover Your Master Key

```powershell
.\Decrypt-MasterKeyBackup.ps1 -BackupFile "master-key.backup"
```

This will prompt for your recovery password and output your 44-character master key.

## Step 2: Use the Master Key

### Option A: In the App
1. Open Simple Secret
2. Click "Decrypt"
3. Paste the master key
4. Click "Decrypt with Key"

### Option B: Without the App
```powershell
.\Decrypt-EnvFile.ps1 -MasterKey "your44charkey==" -EncryptedFile ".env.encrypted"
```

This decrypts your `.env.encrypted` file to `.env`.

## Security Notes

- Delete `.env` after extracting what you need - it contains plaintext secrets
- Never share your master key or recovery password
- These scripts require PowerShell 5.1+ (included in Windows 10/11)

## Technical Details

### Backup Encryption
- **Key Derivation:** PBKDF2-SHA256, 100,000 iterations
- **Encryption:** AES-256-CBC
- **Master Key:** 32 bytes (44 characters base64)

### .env.encrypted Format
- **Format:** JSON with metadata and base64-encoded data
- **Data Structure:** IV (16 bytes) + AES-256-CBC ciphertext
- **Encryption:** AES-256-CBC with master key
