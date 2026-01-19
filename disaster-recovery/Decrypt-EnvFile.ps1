# Decrypt-EnvFile.ps1
# Decrypts .env.encrypted using your master key (without needing the app)
#
# Usage: .\Decrypt-EnvFile.ps1 -MasterKey "your44charkey==" -EncryptedFile ".env.encrypted"

param(
    [Parameter(Mandatory=$false)]
    [string]$MasterKey = "",

    [Parameter(Mandatory=$false)]
    [string]$EncryptedFile = ".env.encrypted",

    [Parameter(Mandatory=$false)]
    [string]$OutputFile = ".env"
)

Write-Host "=== Simple Secret - Decrypt .env File ===" -ForegroundColor Cyan
Write-Host ""

# Get master key if not provided
if ($MasterKey -eq "") {
    $MasterKey = Read-Host "Enter your 44-character master key"
}

# Validate master key
if ($MasterKey.Length -ne 44) {
    Write-Error "Invalid master key. Expected 44 characters, got $($MasterKey.Length)"
    exit 1
}

# Check encrypted file exists
if (-not (Test-Path $EncryptedFile)) {
    Write-Error "Encrypted file not found: $EncryptedFile"
    exit 1
}

Write-Host "Encrypted file: $EncryptedFile" -ForegroundColor Gray
Write-Host "Output file: $OutputFile" -ForegroundColor Gray
Write-Host ""
Write-Host "Decrypting..." -ForegroundColor Yellow

try {
    # Read encrypted file (JSON format)
    $encryptedData = Get-Content $EncryptedFile -Raw | ConvertFrom-Json

    # Decode base64 data (IV + ciphertext)
    $keyBytes = [Convert]::FromBase64String($MasterKey)
    $data = [Convert]::FromBase64String($encryptedData.Data)

    # Extract IV (first 16 bytes) and ciphertext (rest)
    $iv = $data[0..15]
    $ciphertext = $data[16..($data.Length - 1)]

    # Create AES decryptor
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.Key = $keyBytes
    $aes.IV = $iv

    # Decrypt
    $decryptor = $aes.CreateDecryptor()
    $decryptedBytes = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
    $plaintext = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)

    # Write to output file
    $plaintext | Out-File -FilePath $OutputFile -Encoding UTF8 -NoNewline

    Write-Host ""
    Write-Host "SUCCESS! Decrypted to: $OutputFile" -ForegroundColor Green
    Write-Host ""
    Write-Host "Your secrets are now in $OutputFile" -ForegroundColor White
    Write-Host "WARNING: Delete $OutputFile after use - it contains plaintext secrets!" -ForegroundColor Yellow
    Write-Host ""

} catch {
    Write-Host ""
    Write-Error "Decryption failed. The master key may be incorrect or the file is corrupted."
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}
