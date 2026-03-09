<#
.SYNOPSIS
    Windows-side installer for scrt2 (WSL daemon).
    Optionally installs WSL if not present.

.DESCRIPTION
    Run this from PowerShell on Windows. It checks for WSL, optionally
    installs it, then launches install.sh inside WSL to set up scrt2.

.PARAMETER InstallWSL
    Also install WSL (Ubuntu) if not already installed.
    Requires administrator privileges and may require a restart.

.EXAMPLE
    # Normal install (WSL already set up)
    .\install.ps1

    # Install WSL first, then scrt2
    .\install.ps1 -InstallWSL
#>
param(
    [switch]$InstallWSL
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  scrt2 installer (Windows bootstrap)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Check/install WSL ──

$wslInstalled = $false
try {
    $wslOutput = wsl --status 2>&1
    if ($LASTEXITCODE -eq 0 -or ($wslOutput -match "Default Distribution")) {
        $wslInstalled = $true
    }
} catch {
    $wslInstalled = $false
}

if (-not $wslInstalled) {
    # Also check if wsl.exe exists but has no distro
    try {
        $distros = wsl --list --quiet 2>&1
        if ($distros -and $distros.Length -gt 0 -and $distros[0] -ne "") {
            $wslInstalled = $true
        }
    } catch {}
}

if (-not $wslInstalled) {
    if ($InstallWSL) {
        Write-Host "WSL not found. Installing..." -ForegroundColor Yellow
        Write-Host ""

        # Check admin privileges
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            Write-Host "ERROR: WSL installation requires administrator privileges." -ForegroundColor Red
            Write-Host ""
            Write-Host "Please run this command in an elevated PowerShell:" -ForegroundColor Yellow
            Write-Host "  Start-Process powershell -Verb RunAs -ArgumentList '-File', '$PSCommandPath', '-InstallWSL'" -ForegroundColor White
            Write-Host ""
            exit 1
        }

        Write-Host "Installing WSL with Ubuntu (this may take a few minutes)..." -ForegroundColor Gray
        wsl --install -d Ubuntu

        if ($LASTEXITCODE -ne 0) {
            Write-Host "ERROR: WSL installation failed." -ForegroundColor Red
            exit 1
        }

        Write-Host ""
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host "  RESTART REQUIRED" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "WSL has been installed but requires a restart." -ForegroundColor Yellow
        Write-Host "After restarting:" -ForegroundColor White
        Write-Host "  1. Open Ubuntu from the Start menu to complete first-time setup" -ForegroundColor Gray
        Write-Host "  2. Create your Linux username and password" -ForegroundColor Gray
        Write-Host "  3. Run this installer again (without -InstallWSL):" -ForegroundColor Gray
        Write-Host "     .\install.ps1" -ForegroundColor White
        Write-Host ""

        $restart = Read-Host "Restart now? (yes/no)"
        if ($restart -eq "yes") {
            Restart-Computer -Force
        }
        exit 0

    } else {
        Write-Host "ERROR: WSL is not installed." -ForegroundColor Red
        Write-Host ""
        Write-Host "Run with -InstallWSL to install it automatically:" -ForegroundColor Yellow
        Write-Host "  .\install.ps1 -InstallWSL" -ForegroundColor White
        Write-Host ""
        Write-Host "Or install manually:" -ForegroundColor Gray
        Write-Host "  wsl --install -d Ubuntu" -ForegroundColor White
        Write-Host ""
        exit 1
    }
} else {
    Write-Host "WSL is installed." -ForegroundColor Green
}

# ── Step 2: Verify a distro is available ──

$distros = (wsl --list --quiet 2>&1) | Where-Object { $_ -and $_.Trim() -ne "" }
if (-not $distros -or $distros.Count -eq 0) {
    Write-Host "ERROR: WSL is installed but no Linux distribution found." -ForegroundColor Red
    Write-Host ""
    Write-Host "Install Ubuntu:" -ForegroundColor Yellow
    Write-Host "  wsl --install -d Ubuntu" -ForegroundColor White
    Write-Host ""
    exit 1
}

$defaultDistro = $distros[0].Trim()
Write-Host "Using WSL distro: $defaultDistro" -ForegroundColor Green

# ── Step 3: Find install.sh relative to this script ──

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$installSh = Join-Path $scriptDir "install.sh"

if (-not (Test-Path $installSh)) {
    Write-Host "ERROR: install.sh not found at $installSh" -ForegroundColor Red
    exit 1
}

# Convert Windows path to WSL path
$wslPath = wsl wslpath -u ($installSh -replace '\\', '/')
Write-Host "Running WSL installer: $wslPath" -ForegroundColor Gray
Write-Host ""

# ── Step 4: Run install.sh inside WSL ──

wsl bash -c "chmod +x '$wslPath' && '$wslPath'"

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  scrt2 installation complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Open a WSL terminal and run:" -ForegroundColor White
    Write-Host "  scrt2 setup-2fa        # Set up 2FA" -ForegroundColor Cyan
    Write-Host "  scrt2 unlock           # Authenticate" -ForegroundColor Cyan
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "ERROR: Installation failed. Check output above." -ForegroundColor Red
    exit 1
}
