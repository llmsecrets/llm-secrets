# Setup.ps1
# scrt setup command - First-time setup wizard for encrypting an existing .env file

function Invoke-ScrtSetup {
    <#
    .SYNOPSIS
    First-time setup wizard - encrypt your existing .env file.

    .DESCRIPTION
    Guides new users through:
    1. Windows Hello authentication setup
    2. Encrypting their existing .env file
    3. Creating .env.encrypted (original .env is preserved as backup)

    .PARAMETER EnvPath
    Path to your existing .env file. Defaults to .env in current directory.

    .EXAMPLE
    scrt setup
    scrt setup --env-path "C:\myproject\.env"
    scrt setup --env-path "..\other-project\.env"
    #>
    param(
        [string]$EnvPath = ""
    )

    Write-ScrtLogOperation -Operation "setup" -Details "envPath=$EnvPath"

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  scrt setup - First Time Setup" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This wizard will:" -ForegroundColor White
    Write-Host "  1. Set up Windows Hello authentication" -ForegroundColor Gray
    Write-Host "  2. Encrypt your .env file" -ForegroundColor Gray
    Write-Host "  3. Keep your original .env as a backup" -ForegroundColor Gray
    Write-Host ""

    # Step 1: Find or ask for .env file
    if (-not $EnvPath) {
        $defaultPath = Join-Path (Get-Location) ".env"
        if (Test-Path $defaultPath) {
            Write-Host "Found .env in current directory." -ForegroundColor Green
            $EnvPath = $defaultPath
        } else {
            Write-Host "No .env file found in current directory." -ForegroundColor Yellow
            Write-Host ""
            $EnvPath = Read-Host "Enter path to your .env file"

            if (-not $EnvPath) {
                Write-ScrtError "No path provided. Exiting."
                return $false
            }
        }
    }

    # Resolve to absolute path
    if (-not [System.IO.Path]::IsPathRooted($EnvPath)) {
        $EnvPath = Join-Path (Get-Location) $EnvPath
    }
    $EnvPath = [System.IO.Path]::GetFullPath($EnvPath)

    # Verify .env exists
    if (-not (Test-Path $EnvPath)) {
        Write-ScrtError ".env file not found at: $EnvPath"
        return $false
    }

    $envDir = Split-Path -Parent $EnvPath
    $envEncPath = Join-Path $envDir ".env.encrypted"
    $envBackupPath = Join-Path $envDir ".env.backup"

    Write-Host ""
    Write-Host "Source:     $EnvPath" -ForegroundColor White
    Write-Host "Encrypted:  $envEncPath" -ForegroundColor White
    Write-Host "Backup:     $envBackupPath" -ForegroundColor Gray
    Write-Host ""

    # Check if already encrypted
    if (Test-Path $envEncPath) {
        Write-ScrtWarning ".env.encrypted already exists in this directory."
        $overwrite = Read-Host "Overwrite? (yes/no)"
        if ($overwrite -ne "yes") {
            Write-Host "Cancelled." -ForegroundColor Gray
            return $false
        }
    }

    # Step 2: Check/setup Windows Hello
    Write-Host ""
    Write-Host "Step 1: Windows Hello Authentication" -ForegroundColor Cyan
    Write-Host "-------------------------------------" -ForegroundColor Gray

    # Check if already initialized
    $hasDpapiKey = Test-DpapiMasterKey

    if (-not $hasDpapiKey) {
        Write-Host "Setting up encryption key with Windows Hello..." -ForegroundColor Gray
        Write-Host ""

        # Authenticate with Windows Hello
        $authResult = Invoke-WindowsHelloAuth
        if (-not $authResult) {
            Write-ScrtError "Windows Hello authentication failed."
            return $false
        }

        # Generate and store master key
        Write-Host ""
        Write-Host "Generating encryption key..." -ForegroundColor Gray

        $keyBytes = New-Object byte[] 32
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($keyBytes)
        $masterKey = [Convert]::ToBase64String($keyBytes)

        $result = Save-DpapiMasterKey -MasterKey $masterKey

        if (-not $result) {
            Write-ScrtError "Failed to store encryption key."
            return $false
        }

        # Show master key for backup
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host "  SAVE THIS MASTER KEY!" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Store this in your password manager:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host $masterKey -ForegroundColor White
        Write-Host ""
        Write-Host "You'll need this key if you:" -ForegroundColor Gray
        Write-Host "  - Move to a new computer" -ForegroundColor Gray
        Write-Host "  - Need to recover your secrets" -ForegroundColor Gray
        Write-Host ""
        Read-Host "Press Enter after you've saved the key"

        # Clear from memory
        $masterKey = $null
        [System.GC]::Collect()

        Write-ScrtSuccess "Encryption key created and secured with Windows Hello"
    } else {
        Write-Host "Encryption key already exists." -ForegroundColor Green

        # Create session
        $sessionKey = Get-SessionKey
        if (-not $sessionKey) {
            Write-Host "Authenticating with Windows Hello..." -ForegroundColor Gray
            $authResult = New-SessionKey
            if (-not $authResult) {
                Write-ScrtError "Windows Hello authentication failed."
                return $false
            }
        }
        Write-ScrtSuccess "Windows Hello session active"
    }

    # Step 3: Create backup of original .env
    Write-Host ""
    Write-Host "Step 2: Backup Original .env" -ForegroundColor Cyan
    Write-Host "-----------------------------" -ForegroundColor Gray

    Copy-Item $EnvPath $envBackupPath -Force
    Write-ScrtSuccess "Original .env backed up to .env.backup"

    # Step 4: Encrypt
    Write-Host ""
    Write-Host "Step 3: Encrypt .env" -ForegroundColor Cyan
    Write-Host "--------------------" -ForegroundColor Gray

    # Need a session for encryption
    $sessionKey = Get-SessionKey
    if (-not $sessionKey) {
        $authResult = New-SessionKey
        if (-not $authResult) {
            Write-ScrtError "Failed to create session for encryption."
            return $false
        }
    }

    $result = Protect-EnvFile -InputPath $EnvPath -OutputPath $envEncPath

    if (-not $result) {
        Write-ScrtError "Encryption failed."
        return $false
    }

    Write-ScrtSuccess ".env encrypted to .env.encrypted"

    # Step 5: Summary
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Setup Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Your files:" -ForegroundColor White
    Write-Host "  .env           - Original (you can delete after testing)" -ForegroundColor Gray
    Write-Host "  .env.backup    - Backup copy" -ForegroundColor Gray
    Write-Host "  .env.encrypted - Encrypted (commit this to git)" -ForegroundColor Green
    Write-Host ""
    Write-Host "Add to .gitignore:" -ForegroundColor Yellow
    Write-Host "  .env" -ForegroundColor White
    Write-Host "  .env.backup" -ForegroundColor White
    Write-Host ""
    Write-Host "CLI Commands:" -ForegroundColor Cyan
    Write-Host "  scrt view              # View your secrets" -ForegroundColor White
    Write-Host "  scrt decrypt           # Decrypt for editing" -ForegroundColor White
    Write-Host "  scrt encrypt --force   # Re-encrypt after editing" -ForegroundColor White
    Write-Host "  scrt run -- <command>  # Run with secrets injected" -ForegroundColor White
    Write-Host ""

    Write-ScrtLogResult -Operation "setup" -Success $true -Details "Setup complete"
    return $true
}
