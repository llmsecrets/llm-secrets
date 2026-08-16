# Recover-MasterKey.ps1 — recover a scrt4 master key from a backup file,
# without scrt4, without a daemon, without your authenticator.
#
# Usage: .\Recover-MasterKey.ps1 [-BackupFile .\encrypted-master-key-instructions.json]
#
# Format (see README.md): PBKDF2-HMAC-SHA256 over the recovery password with
# the stored Salt and Iterations -> 32-byte key; AES-256-CBC + PKCS#7 with the
# stored IV. Uses only .NET, so it runs on a clean Windows box with no installs.

[CmdletBinding()]
param(
    [string]$BackupFile = 'encrypted-master-key-instructions.json'
)

$ErrorActionPreference = 'Stop'

function Die($msg) { Write-Host "error: $msg" -ForegroundColor Red; exit 1 }

if (-not (Test-Path $BackupFile)) {
    Die @"
backup file not found: $BackupFile

Usage: .\Recover-MasterKey.ps1 [-BackupFile <path>]
Create one with:  scrt4 unlock; scrt4 backup-key --save $env:USERPROFILE\Desktop
"@
}

try { $backup = Get-Content $BackupFile -Raw | ConvertFrom-Json }
catch { Die "could not parse $BackupFile as JSON: $($_.Exception.Message)" }

if (-not $backup.Salt -or -not $backup.IV -or -not $backup.EncryptedMasterKey) {
    Die @"
backup file is missing Salt, IV or EncryptedMasterKey — is this a scrt4 backup?
v1/v3 LLM Secrets backups use a different format; see README.md.
"@
}

$created = if ($backup.CreatedAt) { $backup.CreatedAt } else { 'unknown' }
$version = if ($backup.Version)   { $backup.Version }   else { '1.0' }
$iters   = 100000
if ($backup.DecryptionInstructions -and $backup.DecryptionInstructions.Iterations) {
    $iters = [int]$backup.DecryptionInstructions.Iterations
}

Write-Host '=== scrt4 master key recovery ===' -ForegroundColor Cyan
Write-Host "  Backup created:    $created"
Write-Host "  Format version:    $version"
Write-Host "  PBKDF2 iterations: $iters"
Write-Host ''

if ($env:SCRT4_TEST_PASSWORD) {
    $password = $env:SCRT4_TEST_PASSWORD
    Write-Host '(using SCRT4_TEST_PASSWORD from environment)' -ForegroundColor Yellow
} else {
    $secure = Read-Host 'Recovery password' -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try   { $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}
if (-not $password) { Die 'no password entered' }

$salt      = [Convert]::FromBase64String($backup.Salt)
$iv        = [Convert]::FromBase64String($backup.IV)
$encrypted = [Convert]::FromBase64String($backup.EncryptedMasterKey)

$aes = $null; $kdf = $null; $decryptor = $null
try {
    $pwBytes = [Text.Encoding]::UTF8.GetBytes($password)
    # Rfc2898DeriveBytes with an explicit hash algorithm — the 3-arg
    # constructor defaults to SHA-1, which would derive the wrong key.
    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
        $pwBytes, $salt, $iters, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $derivedKey = $kdf.GetBytes(32)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key     = $derivedKey
    $aes.IV      = $iv

    $decryptor = $aes.CreateDecryptor()
    $plain = $decryptor.TransformFinalBlock($encrypted, 0, $encrypted.Length)
    $masterKey = [Text.Encoding]::UTF8.GetString($plain).Trim()
} catch {
    Die @"
decryption failed — check the recovery password.

The password is the one you typed when running ``scrt4 backup-key --save``,
not your vault PIN and not your authenticator PIN.
"@
} finally {
    if ($decryptor) { $decryptor.Dispose() }
    if ($aes)       { $aes.Dispose() }
    if ($kdf)       { $kdf.Dispose() }
}

if (-not $masterKey) { Die 'decryption produced an empty key — the backup may be corrupt' }

Write-Host ''
Write-Host '=== RECOVERED MASTER KEY ===' -ForegroundColor Green
Write-Host $masterKey
Write-Host ''
Write-Host 'Next: on the target machine run'
Write-Host '    scrt4 setup          # enroll a new authenticator'
Write-Host '    scrt4 restore-key    # paste the key above'
Write-Host ''
Write-Host 'This key is the entire vault. Clear your scrollback when you are done.' -ForegroundColor Yellow
