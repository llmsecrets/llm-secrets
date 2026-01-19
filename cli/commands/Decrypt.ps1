# Decrypt.ps1
# scrt decrypt command

function Invoke-ScrtDecrypt {
    <#
    .SYNOPSIS
    Decrypts .env.encrypted to .env
    #>
    param(
        [switch]$Preview,
        [switch]$MasterKey
    )

    Write-ScrtLogOperation -Operation "decrypt" -Details "preview=$Preview, masterKey=$MasterKey"

    Write-Host ""
    Write-Host "scrt decrypt" -ForegroundColor Cyan
    Write-Host ""

    # Find files
    $scrtRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $envPath = Join-Path $scrtRoot ".env"
    $envEncPath = Join-Path $scrtRoot ".env.encrypted"
    $envTmpPath = "$envPath.tmp"

    # Handle authentication FIRST (unless master key mode)
    $masterKeyValue = ""
    if (-not $MasterKey) {
        # Check for valid session BEFORE checking file
        $sessionKey = Get-SessionKey
        if (-not $sessionKey) {
            Write-ScrtError "No active session. Run 'scrt auth' first."
            Write-Host "Or use --master-key for recovery mode." -ForegroundColor Gray
            Write-ScrtLogResult -Operation "decrypt" -Success $false -Details "No session"
            exit 2
        }
    }

    # Check source exists
    if (-not (Test-Path $envEncPath)) {
        Write-ScrtError ".env.encrypted not found."
        Write-Host "Run 'scrt encrypt' first to create it." -ForegroundColor Gray
        Write-ScrtLogResult -Operation "decrypt" -Success $false -Details "Source not found"
        exit 3
    }

    # Handle master key mode
    if ($MasterKey) {
        Write-Host "MASTER KEY RECOVERY MODE" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Paste your 44-character master key (it will be hidden):" -ForegroundColor Gray

        # Use GUI password dialog for safety
        $secureKey = Show-PasswordDialog -Title "Master Key Recovery" -Message "Enter your 44-character master key:"
        if (-not $secureKey) {
            Write-ScrtError "Master key entry cancelled."
            Write-ScrtLogResult -Operation "decrypt" -Success $false -Details "Master key cancelled"
            exit 1
        }

        # Convert to plain text
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
        $masterKeyValue = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

        if ($masterKeyValue.Length -ne 44) {
            Write-ScrtError "Invalid master key format. Expected 44 characters, got $($masterKeyValue.Length)."
            $masterKeyValue = $null
            Write-ScrtLogResult -Operation "decrypt" -Success $false -Details "Invalid master key"
            exit 1
        }
    }

    # Preview mode
    if ($Preview) {
        Write-Host "Decrypting for preview (first 5 lines)..." -ForegroundColor Gray

        if ($masterKeyValue) {
            $content = Unprotect-EnvFile -InputPath $envEncPath -InMemory -MasterKey $masterKeyValue
        } else {
            $content = Unprotect-EnvFile -InputPath $envEncPath -InMemory
        }

        if (-not $content) {
            Write-ScrtError "Decryption failed."
            Write-ScrtLogResult -Operation "decrypt" -Success $false -Details "Decryption failed"
            exit 1
        }

        Write-Host ""
        Write-Host "PREVIEW (first 5 lines):" -ForegroundColor Yellow
        Write-Host "-------------------------" -ForegroundColor Gray

        $lines = $content.Split("`n")
        $count = [Math]::Min(5, $lines.Count)
        for ($i = 0; $i -lt $count; $i++) {
            Write-Host $lines[$i]
        }

        if ($lines.Count -gt 5) {
            Write-Host "... ($($lines.Count - 5) more lines)" -ForegroundColor Gray
        }

        Write-Host ""
        Write-ScrtSuccess "Preview complete. No file written."

        # Clear from memory
        $content = $null
        $masterKeyValue = $null
        [System.GC]::Collect()

        Write-ScrtLogResult -Operation "decrypt" -Success $true -Details "Preview only"
        return $true
    }

    # Full decrypt mode
    if (Test-Path $envPath) {
        Write-ScrtWarning ".env already exists. It will be overwritten."
    }

    Write-Host "Decrypting .env.encrypted..." -ForegroundColor Gray

    # Decrypt to temp file first
    if ($masterKeyValue) {
        $result = Unprotect-EnvFile -InputPath $envEncPath -OutputPath $envTmpPath -MasterKey $masterKeyValue
    } else {
        $result = Unprotect-EnvFile -InputPath $envEncPath -OutputPath $envTmpPath
    }

    if (-not $result) {
        Write-ScrtError "Decryption failed."
        if (Test-Path $envTmpPath) {
            Remove-Item $envTmpPath -Force
        }
        Write-ScrtLogResult -Operation "decrypt" -Success $false -Details "Decryption failed"
        exit 1
    }

    # Verify temp file
    if (-not (Test-Path $envTmpPath)) {
        Write-ScrtError "Temp file not created."
        Write-ScrtLogResult -Operation "decrypt" -Success $false -Details "Temp file missing"
        exit 1
    }

    # Move to final location
    Move-Item $envTmpPath $envPath -Force

    $envSize = (Get-Item $envPath).Length
    Write-Host ""
    Write-ScrtSuccess "Decrypted to .env ($envSize bytes)"
    Write-Host ""
    Write-ScrtWarning "PLAINTEXT .env now exists. Remember to re-encrypt after editing!"
    Write-Host "Run 'scrt encrypt' when done editing." -ForegroundColor Gray
    Write-Host ""

    # Clear sensitive data
    $masterKeyValue = $null
    [System.GC]::Collect()

    Write-ScrtLogResult -Operation "decrypt" -Success $true -Details "Decrypted $envSize bytes"
    return $true
}
