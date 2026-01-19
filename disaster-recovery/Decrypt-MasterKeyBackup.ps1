# Decrypt-MasterKeyBackup.ps1
# Recovers your master key from a backup file using your recovery password
#
# Usage: .\Decrypt-MasterKeyBackup.ps1 -BackupFile "master-key.backup"

param(
    [Parameter(Mandatory=$false)]
    [string]$BackupFile = "master-key.backup"
)

if (-not (Test-Path $BackupFile)) {
    Write-Error "Backup file not found: $BackupFile"
    exit 1
}

Write-Host "=== Simple Secret - Master Key Recovery ===" -ForegroundColor Cyan
Write-Host ""

# Read backup file
$backup = Get-Content $BackupFile -Raw | ConvertFrom-Json

Write-Host "Backup created: $($backup.CreatedAt)" -ForegroundColor Gray
Write-Host "Security mode: $($backup.SecurityMode)" -ForegroundColor Gray
Write-Host ""

# Get recovery password
$password = Read-Host "Enter your recovery password" -AsSecureString

# Convert SecureString to plain text
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
$plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

Write-Host ""
Write-Host "Decrypting..." -ForegroundColor Yellow

try {
    # Get salt and derive key using PBKDF2
    $salt = [Convert]::FromBase64String($backup.Salt)
    $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
        $plainPassword,
        $salt,
        100000,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )
    $derivedKey = $pbkdf2.GetBytes(32)

    # Decrypt master key using AES-256-CBC
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.Key = $derivedKey
    $aes.IV = [Convert]::FromBase64String($backup.IV)

    $encryptedMasterKey = [Convert]::FromBase64String($backup.EncryptedMasterKey)
    $decryptor = $aes.CreateDecryptor()
    $decryptedBytes = $decryptor.TransformFinalBlock($encryptedMasterKey, 0, $encryptedMasterKey.Length)
    $masterKey = [System.Text.Encoding]::UTF8.GetString($decryptedBytes).TrimEnd([char]0)

    Write-Host ""
    Write-Host "SUCCESS! Your master key is:" -ForegroundColor Green
    Write-Host ""
    Write-Host $masterKey -ForegroundColor White
    Write-Host ""
    Write-Host "Key length: $($masterKey.Length) characters" -ForegroundColor Gray
    Write-Host ""
    Write-Host "=== What to do next ===" -ForegroundColor Cyan
    Write-Host "Option 1: In the app, click 'Decrypt', paste this key, click 'Decrypt with Key'" -ForegroundColor White
    Write-Host "Option 2: Run Decrypt-EnvFile.ps1 to decrypt .env.encrypted without the app" -ForegroundColor White
    Write-Host ""

    # Clear sensitive data
    $plainPassword = $null
    $derivedKey = $null

} catch {
    Write-Host ""
    Write-Error "Decryption failed. Check your recovery password."
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}
