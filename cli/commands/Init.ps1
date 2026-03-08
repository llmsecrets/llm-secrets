# Init.ps1
# scrt init command - Setup wizard

function Invoke-ScrtInit {
    <#
    .SYNOPSIS
    Setup wizard for scrt secrets management.

    .PARAMETER InstallWSL
    Also install WSL (Ubuntu) if not already installed.
    Requires administrator privileges and may need a restart.

    .EXAMPLE
    scrt init
    scrt init --install-wsl
    scrt init -Mode simple --install-wsl
    #>
    param(
        [ValidateSet("simple", "advanced", "")]
        [string]$Mode = "",
        [switch]$Force,
        [Alias("install-wsl")]
        [switch]$InstallWSL
    )

    Write-ScrtLogOperation -Operation "init" -Details "mode=$Mode, force=$Force"

    Write-ScrtHeader "scrt init - Setup Wizard"

    # Handle WSL installation if requested
    if ($InstallWSL) {
        Install-WSLDependency
    }

    # Check current state
    $settings = Get-Settings
    $hasDpapiKey = Test-DpapiMasterKey
    $hasKeePass = Test-KeePassDatabase

    # Check if already set up
    $existingSetup = $hasDpapiKey -or $hasKeePass
    if ($existingSetup -and -not $Force) {
        Write-ScrtInfo "Existing setup detected:"
        if ($hasDpapiKey) { Write-Host "  - DPAPI master key exists" -ForegroundColor Gray }
        if ($hasKeePass) { Write-Host "  - KeePass database exists" -ForegroundColor Gray }
        Write-Host "  - Current mode: $($settings.securityMode)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Use --force to re-initialize." -ForegroundColor Yellow
        Write-Host ""
        Write-ScrtLogResult -Operation "init" -Success $true -Details "Already configured"
        return $true
    }

    # Determine mode
    if ($Mode -eq "") {
        # Interactive mode selection
        Write-Host "Choose your security mode:" -ForegroundColor White
        Write-Host ""
        Write-Host "  [1] SIMPLE MODE (Recommended)" -ForegroundColor Green
        Write-Host "      - Windows Hello (PIN/biometric) only" -ForegroundColor Gray
        Write-Host "      - One authentication step" -ForegroundColor Gray
        Write-Host "      - Master key stored with DPAPI encryption" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [2] ADVANCED MODE" -ForegroundColor Yellow
        Write-Host "      - Windows Hello + KeePass password" -ForegroundColor Gray
        Write-Host "      - Two authentication steps" -ForegroundColor Gray
        Write-Host "      - Higher security for shared machines" -ForegroundColor Gray
        Write-Host ""

        $choice = Read-Host "Enter choice (1 or 2)"

        switch ($choice) {
            "1" { $Mode = "simple" }
            "2" { $Mode = "advanced" }
            default {
                Write-ScrtError "Invalid choice. Please enter 1 or 2."
                Write-ScrtLogResult -Operation "init" -Success $false -Details "Invalid choice"
                return $false
            }
        }
    }

    # Setup based on mode
    if ($Mode -eq "simple") {
        return Initialize-SimpleMode -Force:$Force
    } else {
        return Initialize-AdvancedMode -Force:$Force
    }
}

function Initialize-SimpleMode {
    param([switch]$Force)

    Write-Host ""
    Write-Host "Setting up SIMPLE MODE..." -ForegroundColor Cyan
    Write-Host ""

    # Windows Hello verification
    Write-Host "Verifying Windows Hello..." -ForegroundColor Gray
    $authResult = Invoke-WindowsHelloAuth
    if (-not $authResult) {
        Write-ScrtError "Windows Hello authentication failed."
        Write-ScrtLogResult -Operation "init" -Success $false -Details "Windows Hello failed"
        return $false
    }

    $hasDpapiKey = Test-DpapiMasterKey
    $hasKeePass = Test-KeePassDatabase

    if ($hasKeePass -and -not $hasDpapiKey) {
        # Migrate from KeePass
        Write-Host ""
        Write-ScrtInfo "KeePass database found. Migrating to DPAPI storage..."

        $keepassPassword = Show-PasswordDialog -Title "Migration" -Message "Enter your KeePass password:"
        if (-not $keepassPassword) {
            Write-ScrtError "Password entry cancelled."
            Write-ScrtLogResult -Operation "init" -Success $false -Details "Migration cancelled"
            return $false
        }

        $masterKey = Get-MasterKeyFromKeePass -DatabasePassword $keepassPassword
        if (-not $masterKey) {
            Write-ScrtError "Failed to retrieve master key from KeePass."
            Write-ScrtLogResult -Operation "init" -Success $false -Details "KeePass retrieval failed"
            return $false
        }

        $result = Save-DpapiMasterKey -MasterKey $masterKey
        $masterKey = $null
        [System.GC]::Collect()

        if (-not $result) {
            Write-ScrtError "Failed to store master key with DPAPI."
            Write-ScrtLogResult -Operation "init" -Success $false -Details "DPAPI storage failed"
            return $false
        }

        Write-ScrtSuccess "Master key migrated from KeePass to DPAPI"

    } elseif ($hasDpapiKey -and -not $Force) {
        Write-ScrtSuccess "DPAPI master key already exists"

    } else {
        # Generate new master key
        Write-Host "Generating new master key..." -ForegroundColor Gray

        $keyBytes = New-Object byte[] 32
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($keyBytes)
        $masterKey = [Convert]::ToBase64String($keyBytes)

        $result = Save-DpapiMasterKey -MasterKey $masterKey

        if (-not $result) {
            Write-ScrtError "Failed to store master key."
            Write-ScrtLogResult -Operation "init" -Success $false -Details "Storage failed"
            return $false
        }

        Write-Host ""
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host "  BACKUP YOUR MASTER KEY!" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Store this key in a password manager:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host $masterKey -ForegroundColor White
        Write-Host ""
        Write-Host "This key is needed if you need to recover your secrets." -ForegroundColor Gray
        Write-Host ""
        Read-Host "Press Enter after you have saved the key"

        $masterKey = $null
        [System.GC]::Collect()
    }

    # Save settings
    $newSettings = @{
        securityMode = "simple"
        masterKeyStorage = "dpapi"
        sessionDuration = 7200
        showSuccessDialog = $true
        advancedSecurity = @{
            enabled = $false
            keepassPath = "EnvCrypto.kdbx"
        }
        backup = @{
            enabled = $true
            frequency = "monthly"
            destination = "google-drive"
            lastBackup = $null
            recoveryPasswordSet = $false
        }
    }
    Set-Settings -Settings $newSettings | Out-Null

    Write-Host ""
    Write-ScrtHeader "Simple Mode Setup Complete!"
    Write-Host "To authenticate: scrt auth" -ForegroundColor Cyan
    Write-Host "You will only need your Windows Hello PIN/biometric." -ForegroundColor Gray
    Write-Host ""

    Write-ScrtLogResult -Operation "init" -Success $true -Details "Simple mode configured"
    return $true
}

function Initialize-AdvancedMode {
    param([switch]$Force)

    Write-Host ""
    Write-Host "Setting up ADVANCED MODE..." -ForegroundColor Cyan
    Write-Host ""

    # Windows Hello verification
    Write-Host "Verifying Windows Hello..." -ForegroundColor Gray
    $authResult = Invoke-WindowsHelloAuth
    if (-not $authResult) {
        Write-ScrtError "Windows Hello authentication failed."
        Write-ScrtLogResult -Operation "init" -Success $false -Details "Windows Hello failed"
        return $false
    }

    $hasKeePass = Test-KeePassDatabase

    if ($hasKeePass -and -not $Force) {
        Write-ScrtSuccess "KeePass database already exists"
    } else {
        # Create new KeePass database
        Write-Host ""
        Write-Host "Creating KeePass database..." -ForegroundColor Gray
        $masterKey = New-MasterKey -ExportKey

        if (-not $masterKey -or $masterKey -eq $false) {
            Write-ScrtError "Failed to create KeePass database."
            Write-ScrtLogResult -Operation "init" -Success $false -Details "KeePass creation failed"
            return $false
        }

        Write-Host ""
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host "  BACKUP YOUR MASTER KEY!" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Store this key in a password manager:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host $masterKey -ForegroundColor White
        Write-Host ""
        Write-Host "This key is needed if you forget your KeePass password." -ForegroundColor Gray
        Write-Host ""
        Read-Host "Press Enter after you have saved the key"

        $masterKey = $null
        [System.GC]::Collect()
    }

    # Save settings
    $newSettings = @{
        securityMode = "advanced"
        masterKeyStorage = "keepass"
        sessionDuration = 7200
        showSuccessDialog = $true
        advancedSecurity = @{
            enabled = $true
            keepassPath = "EnvCrypto.kdbx"
        }
        backup = @{
            enabled = $true
            frequency = "monthly"
            destination = "google-drive"
            lastBackup = $null
            recoveryPasswordSet = $false
        }
    }
    Set-Settings -Settings $newSettings | Out-Null

    Write-Host ""
    Write-ScrtHeader "Advanced Mode Setup Complete!"
    Write-Host "To authenticate: scrt auth" -ForegroundColor Cyan
    Write-Host "You will need Windows Hello + your KeePass password." -ForegroundColor Gray
    Write-Host ""

    Write-ScrtLogResult -Operation "init" -Success $true -Details "Advanced mode configured"
    return $true
}

function Install-WSLDependency {
    <#
    .SYNOPSIS
    Checks for WSL and installs it if missing.
    Required for scrt's WSL daemon component.
    #>

    Write-Host ""
    Write-Host "Checking WSL installation..." -ForegroundColor Cyan

    $wslInstalled = $false
    try {
        $null = wsl --status 2>&1
        $distros = (wsl --list --quiet 2>&1) | Where-Object { $_ -and $_.Trim() -ne "" }
        if ($distros -and $distros.Count -gt 0) {
            $wslInstalled = $true
        }
    } catch {}

    if ($wslInstalled) {
        Write-Host "WSL is already installed." -ForegroundColor Green
        Write-Host ""
        return
    }

    Write-Host "WSL not found. Installing..." -ForegroundColor Yellow
    Write-Host ""

    # Check admin privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "WSL installation requires administrator privileges." -ForegroundColor Red
        Write-Host ""
        Write-Host "Option 1: Re-run as admin:" -ForegroundColor Yellow
        Write-Host "  Start-Process powershell -Verb RunAs -ArgumentList 'scrt init --install-wsl'" -ForegroundColor White
        Write-Host ""
        Write-Host "Option 2: Install WSL manually:" -ForegroundColor Yellow
        Write-Host "  wsl --install -d Ubuntu" -ForegroundColor White
        Write-Host ""
        return
    }

    Write-Host "Installing WSL with Ubuntu (this may take a few minutes)..." -ForegroundColor Gray
    wsl --install -d Ubuntu

    if ($LASTEXITCODE -ne 0) {
        Write-Host "WSL installation failed. Try manually: wsl --install -d Ubuntu" -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "  RESTART REQUIRED" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "WSL installed. After restarting:" -ForegroundColor Yellow
    Write-Host "  1. Open Ubuntu from Start menu (first-time setup)" -ForegroundColor Gray
    Write-Host "  2. Create your Linux username and password" -ForegroundColor Gray
    Write-Host "  3. Run 'scrt init' again to continue setup" -ForegroundColor Gray
    Write-Host ""

    $restart = Read-Host "Restart now? (yes/no)"
    if ($restart -eq "yes") {
        Restart-Computer -Force
    }
}
