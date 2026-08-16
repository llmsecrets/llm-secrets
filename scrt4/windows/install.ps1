# install.ps1 -- build and install scrt4 natively on Windows.
#
# Usage (from the repo root or windows\):
#   powershell -ExecutionPolicy Bypass -File windows\install.ps1
#   ... -InstallDir C:\tools\scrt4       # custom location
#   ... -NoBuild                          # skip cargo, copy existing binaries
#   ... -RegisterLogonTask                # start the daemon at logon
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'scrt4'),
    [switch]$NoBuild,
    [switch]$RegisterLogonTask
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$daemonDir = Join-Path $repoRoot 'daemon'

Write-Host "scrt4 Windows install -> $InstallDir" -ForegroundColor Cyan

# 1. Build the daemon (+ Rust CLI) unless -NoBuild.
if (-not $NoBuild) {
    Write-Host 'Building daemon (cargo build --release)...' -ForegroundColor Cyan
    Push-Location $daemonDir
    try {
        cargo build --release
        if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
    } finally {
        Pop-Location
    }
}

$daemonExe = Join-Path $daemonDir 'target\release\scrt4-daemon.exe'
$rustCli = Join-Path $daemonDir 'target\release\scrt4.exe'
if (-not (Test-Path $daemonExe)) {
    throw "Daemon binary not found: $daemonExe (build first or drop -NoBuild)"
}

# 2. Copy binaries + PowerShell client.
# A running daemon holds scrt4-daemon.exe open, so stop it first or the copy
# fails with a sharing violation. Any command auto-starts it again afterwards.
$running = Get-Process -Name 'scrt4-daemon' -ErrorAction SilentlyContinue
if ($running) {
    Write-Host 'Stopping running scrt4-daemon (it will restart on next command)...' -ForegroundColor Yellow
    $running | Stop-Process -Force
    Start-Sleep -Milliseconds 500
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $InstallDir 'scrt4') | Out-Null

Copy-Item $daemonExe (Join-Path $InstallDir 'scrt4-daemon.exe') -Force
if (Test-Path $rustCli) {
    # Rust CLI installed under a different name so `scrt4` resolves to the
    # PowerShell client (scrt4.cmd); the Rust CLI remains available for
    # smoke tests as scrt4-rs.
    Copy-Item $rustCli (Join-Path $InstallDir 'scrt4-rs.exe') -Force
}
Copy-Item (Join-Path $PSScriptRoot 'scrt4\scrt4.psd1') (Join-Path $InstallDir 'scrt4\scrt4.psd1') -Force
Copy-Item (Join-Path $PSScriptRoot 'scrt4\scrt4.psm1') (Join-Path $InstallDir 'scrt4\scrt4.psm1') -Force
Copy-Item (Join-Path $PSScriptRoot 'scrt4-cli.ps1') (Join-Path $InstallDir 'scrt4-cli.ps1') -Force
Copy-Item (Join-Path $PSScriptRoot 'scrt4.cmd') (Join-Path $InstallDir 'scrt4.cmd') -Force
# Remove a stale top-level scrt4.ps1 from a pre-0.3.1 install: on PATH it
# shadows scrt4.cmd in PowerShell and reintroduces the execution-policy block.
$staleShim = Join-Path $InstallDir 'scrt4.ps1'
if (Test-Path $staleShim) { Remove-Item -Force $staleShim; Write-Host "Removed stale scrt4.ps1 (shadowed scrt4.cmd)." -ForegroundColor Yellow }

# 3. Add the install dir to the user PATH if absent.
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($null -eq $userPath) { $userPath = '' }
$onPath = $false
foreach ($entry in $userPath.Split(';')) {
    if ($entry.TrimEnd('\') -ieq $InstallDir.TrimEnd('\')) { $onPath = $true }
}
if (-not $onPath) {
    [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $InstallDir), 'User')
    Write-Host "Added $InstallDir to user PATH (open a new terminal to pick it up)." -ForegroundColor Yellow
}

# 4. ACL-harden the vault directory: owner + SYSTEM only. This is the
# Windows counterpart of the chmod-0600 calls the daemon makes on Unix.
# Built explicitly rather than with `icacls /inheritance:r /grant:r`, which
# leaves the inherited BUILTIN\Administrators ACE in place.
#
# As on Unix (where chmod 0600 does not stop root), this is not a boundary
# against local administrators: they hold SeTakeOwnership/SeBackup and can
# read the vault regardless. It keeps other standard users out.
$configDir = Join-Path $env:USERPROFILE '.scrt4'
New-Item -ItemType Directory -Force -Path $configDir | Out-Null

# icacls, not Set-Acl: Set-Acl writes the audit section and so demands
# SeSecurityPrivilege, which a standard (non-elevated) user does not hold.
# SIDs rather than names so this survives non-English Windows:
#   S-1-5-18     SYSTEM
#   S-1-5-32-544 BUILTIN\Administrators
$meSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

& icacls $configDir /inheritance:r /grant:r "*${meSid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
$granted = ($LASTEXITCODE -eq 0)
# /inheritance:r keeps the Administrators ACE; drop it explicitly.
& icacls $configDir /remove:g '*S-1-5-32-544' | Out-Null
$removed = ($LASTEXITCODE -eq 0)

if ($granted -and $removed) {
    Write-Host "Hardened ACLs on $configDir (owner + SYSTEM only)." -ForegroundColor Cyan
} else {
    Write-Host "WARNING: could not fully harden ACLs on $configDir." -ForegroundColor Yellow
    Write-Host '         The vault is still encrypted; this is defense-in-depth only.' -ForegroundColor Yellow
}

# 5. Optional: run the daemon at logon.
if ($RegisterLogonTask) {
    $action = New-ScheduledTaskAction -Execute (Join-Path $InstallDir 'scrt4-daemon.exe')
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $settings = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName 'scrt4-daemon' -Action $action -Trigger $trigger `
        -Settings $settings -Force | Out-Null
    Write-Host "Registered logon task 'scrt4-daemon'." -ForegroundColor Cyan
}

Write-Host ''
Write-Host 'Installed. Quick start (new terminal):' -ForegroundColor Green
Write-Host '  scrt4 daemon          # or let any command auto-start it'
Write-Host '  scrt4 setup           # register your passkey (Windows Hello works in-browser)'
Write-Host '  scrt4 unlock          # first unlock (relay page)'
Write-Host '  scrt4 setup --local   # add a Windows Hello passkey for phone-free unlocks'
Write-Host '  scrt4 add API_KEY=... ; scrt4 run "curl -H ""Authorization: Bearer $env[API_KEY]"" ..."'
