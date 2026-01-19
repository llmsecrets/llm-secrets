# Encrypt.ps1
# scrt encrypt command

function Invoke-ScrtEncrypt {
    <#
    .SYNOPSIS
    Encrypts .env to .env.encrypted
    #>
    param(
        [switch]$Force,
        [switch]$Keep
    )

    Write-ScrtLogOperation -Operation "encrypt" -Details "force=$Force, keep=$Keep"

    Write-Host ""
    Write-Host "scrt encrypt" -ForegroundColor Cyan
    Write-Host ""

    # Check for valid session
    $sessionKey = Get-SessionKey
    if (-not $sessionKey) {
        Write-ScrtError "No active session. Run 'scrt auth' first."
        Write-ScrtLogResult -Operation "encrypt" -Success $false -Details "No session"
        exit 2
    }

    # Find files
    $scrtRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $envPath = Join-Path $scrtRoot ".env"
    $envEncPath = Join-Path $scrtRoot ".env.encrypted"
    $envEncTmpPath = "$envEncPath.tmp"
    $envEncBakPath = "$envEncPath.bak"

    # Check source exists
    if (-not (Test-Path $envPath)) {
        Write-ScrtError ".env file not found."
        Write-Host "Create or restore a .env file first." -ForegroundColor Gray
        Write-ScrtLogResult -Operation "encrypt" -Success $false -Details ".env not found"
        exit 3
    }

    # Check destination
    if ((Test-Path $envEncPath) -and -not $Force) {
        Write-ScrtWarning ".env.encrypted already exists."
        Write-Host "Use --force to overwrite." -ForegroundColor Gray
        Write-ScrtLogResult -Operation "encrypt" -Success $false -Details "Destination exists, no --force"
        exit 1
    }

    # Get file size for logging
    $envSize = (Get-Item $envPath).Length
    Write-Host "Encrypting .env ($envSize bytes)..." -ForegroundColor Gray

    # Step 1: Encrypt to temp file
    Write-ScrtLog -Message "Encrypting to temp file: $envEncTmpPath"
    $result = Protect-EnvFile -InputPath $envPath -OutputPath $envEncTmpPath

    if (-not $result) {
        Write-ScrtError "Encryption failed."
        if (Test-Path $envEncTmpPath) {
            Remove-Item $envEncTmpPath -Force
        }
        Write-ScrtLogResult -Operation "encrypt" -Success $false -Details "Encryption failed"
        exit 1
    }

    # Step 2: Verify temp file
    if (-not (Test-Path $envEncTmpPath)) {
        Write-ScrtError "Temp encrypted file not created."
        Write-ScrtLogResult -Operation "encrypt" -Success $false -Details "Temp file missing"
        exit 1
    }

    $tmpSize = (Get-Item $envEncTmpPath).Length
    if ($tmpSize -lt 50) {
        Write-ScrtError "Encrypted file too small - something went wrong."
        Remove-Item $envEncTmpPath -Force
        Write-ScrtLogResult -Operation "encrypt" -Success $false -Details "Encrypted file too small"
        exit 1
    }

    # Step 3: Backup existing encrypted file
    if (Test-Path $envEncPath) {
        Write-ScrtLog -Message "Backing up existing encrypted file to: $envEncBakPath"
        Copy-Item $envEncPath $envEncBakPath -Force
    }

    # Step 4: Move temp to final
    Write-ScrtLog -Message "Activating encrypted file: $envEncTmpPath -> $envEncPath"
    Move-Item $envEncTmpPath $envEncPath -Force

    # Step 5: Delete plaintext (unless --keep)
    if (-not $Keep) {
        Write-ScrtLog -Message "Removing plaintext .env"
        Remove-Item $envPath -Force
        Write-Host ""
        Write-ScrtSuccess "Encrypted .env to .env.encrypted"
        Write-ScrtInfo "Plaintext .env deleted for security."
    } else {
        Write-Host ""
        Write-ScrtSuccess "Encrypted .env to .env.encrypted"
        Write-ScrtWarning "Plaintext .env kept (use with caution)."
    }

    Write-Host ""
    Write-ScrtLogResult -Operation "encrypt" -Success $true -Details "Encrypted $envSize bytes"

    return $true
}
