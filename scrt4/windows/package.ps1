# package.ps1 -- build a self-contained scrt4 bundle for another Windows machine.
#
# Produces scrt4-windows-<version>.zip containing the daemon, the PowerShell
# client, and a bootstrap installer. The target machine needs NOTHING
# pre-installed: no Rust, no vcpkg, no OpenSSL, no Python. It just unzips and
# runs install.ps1.
#
#   powershell -ExecutionPolicy Bypass -File windows\package.ps1
#   ... -Upload            # also push to GCS and print the one-liner
param(
    [string]$OutDir = (Join-Path $env:USERPROFILE 'Desktop'),
    [switch]$SkipBuild,
    [switch]$Upload,
    [string]$Bucket = 'scrt4-dist'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$daemonDir = Join-Path $repoRoot 'daemon'

if (-not $SkipBuild) {
    Write-Host 'Building daemon (no OpenSSL, no vcpkg -- just the Rust toolchain)...' -ForegroundColor Cyan
    Push-Location $daemonDir
    try {
        cargo build --release
        if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
    } finally { Pop-Location }
}

$daemonExe = Join-Path $daemonDir 'target\release\scrt4-daemon.exe'
$rustCli   = Join-Path $daemonDir 'target\release\scrt4.exe'
if (-not (Test-Path $daemonExe)) { throw "Missing $daemonExe" }

# Stage the bundle.
$stage = Join-Path ([System.IO.Path]::GetTempPath()) ('scrt4-pkg-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path (Join-Path $stage 'scrt4') | Out-Null

Copy-Item $daemonExe (Join-Path $stage 'scrt4-daemon.exe') -Force
if (Test-Path $rustCli) { Copy-Item $rustCli (Join-Path $stage 'scrt4-rs.exe') -Force }
Copy-Item (Join-Path $PSScriptRoot 'scrt4\scrt4.psd1') (Join-Path $stage 'scrt4\scrt4.psd1') -Force
Copy-Item (Join-Path $PSScriptRoot 'scrt4\scrt4.psm1') (Join-Path $stage 'scrt4\scrt4.psm1') -Force
Copy-Item (Join-Path $PSScriptRoot 'scrt4-cli.ps1') (Join-Path $stage 'scrt4-cli.ps1') -Force
Copy-Item (Join-Path $PSScriptRoot 'scrt4.cmd') (Join-Path $stage 'scrt4.cmd') -Force

# A self-contained installer: no repo, no build, no dependencies.
@'
# install.ps1 -- install a prebuilt scrt4 on this machine.
# Nothing to compile and nothing to pre-install. Just run it.
param([string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'scrt4'))
$ErrorActionPreference = 'Stop'

$running = Get-Process -Name 'scrt4-daemon' -ErrorAction SilentlyContinue
if ($running) {
    Write-Host 'Stopping running scrt4-daemon...' -ForegroundColor Yellow
    $running | Stop-Process -Force; Start-Sleep -Milliseconds 500
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item (Join-Path $PSScriptRoot '*') $InstallDir -Recurse -Force -Exclude 'install.ps1'

# Remove a stale top-level scrt4.ps1 from a pre-0.3.1 install. On PATH it
# shadows scrt4.cmd in PowerShell and reintroduces the "running scripts is
# disabled" (Restricted policy) block. The client is now scrt4-cli.ps1.
$staleShim = Join-Path $InstallDir 'scrt4.ps1'
if (Test-Path $staleShim) { Remove-Item -Force $staleShim; Write-Host 'Removed stale scrt4.ps1 (was shadowing scrt4.cmd).' -ForegroundColor Yellow }

# PATH (user scope; no admin needed)
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($null -eq $userPath) { $userPath = '' }
$onPath = $false
foreach ($e in $userPath.Split(';')) { if ($e.TrimEnd('\') -ieq $InstallDir.TrimEnd('\')) { $onPath = $true } }
if (-not $onPath) {
    [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $InstallDir), 'User')
    Write-Host "Added $InstallDir to your PATH (open a NEW terminal to pick it up)." -ForegroundColor Yellow
}

# Vault ACL: owner + SYSTEM only. icacls, not Set-Acl -- Set-Acl writes the audit
# section and demands SeSecurityPrivilege, which a standard user does not hold.
$configDir = Join-Path $env:USERPROFILE '.scrt4'
New-Item -ItemType Directory -Force -Path $configDir | Out-Null
$meSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls $configDir /inheritance:r /grant:r "*${meSid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
& icacls $configDir /remove:g '*S-1-5-32-544' | Out-Null   # drop inherited Administrators
Write-Host "Hardened ACLs on $configDir (you + SYSTEM only)." -ForegroundColor Cyan

Write-Host ''
Write-Host 'scrt4 installed. In a NEW terminal:' -ForegroundColor Green
Write-Host '  scrt4 help'
Write-Host '  scrt4 setup           # enroll a passkey (browser opens; pick a SYNCING'
Write-Host '                        # passkey if you want to open the vault on a phone)'
Write-Host '  scrt4 unlock'
Write-Host '  scrt4 setup --local   # add a Windows Hello passkey -> phone-free unlocks'
'@ | Set-Content -Path (Join-Path $stage 'install.ps1') -Encoding UTF8

# README so the zip explains itself.
@'
scrt4 -- prebuilt Windows bundle
================================
Nothing to install first. No Rust, no vcpkg, no OpenSSL, no Python.

    powershell -ExecutionPolicy Bypass -File .\install.ps1

Then open a NEW terminal (for PATH) and run:  scrt4 help

Contents:
  scrt4-daemon.exe   the daemon (named-pipe transport, \\.\pipe\scrt4-<user>)
  scrt4.cmd          the CLI entry point (works in cmd.exe AND PowerShell,
                     no execution-policy change needed)
  scrt4-cli.ps1      the client implementation (launched by scrt4.cmd)
  scrt4\             the PowerShell client module
  scrt4-rs.exe       the Rust CLI (smoke tests; the PS client is the real one)

The daemon auto-starts on first command. Vault lives in %USERPROFILE%\.scrt4.
'@ | Set-Content -Path (Join-Path $stage 'README.txt') -Encoding UTF8

$version = (Get-Date -Format 'yyyyMMdd')
$zip = Join-Path $OutDir "scrt4-windows-$version.zip"
Remove-Item -Force $zip -ErrorAction SilentlyContinue
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -CompressionLevel Optimal

$size = [math]::Round((Get-Item $zip).Length / 1MB, 1)
$sha = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
Remove-Item -Recurse -Force $stage

Write-Host ''
Write-Host "Bundle: $zip  (${size} MB)" -ForegroundColor Green
Write-Host "SHA256: $sha"

if ($Upload) {
    Write-Host ''
    Write-Host "Uploading to gs://$Bucket ..." -ForegroundColor Cyan
    & gsutil cp $zip "gs://$Bucket/" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'upload failed (does the bucket exist? see -Bucket)' }
    $url = "https://storage.googleapis.com/$Bucket/scrt4-windows-$version.zip"
    Write-Host "Uploaded: $url" -ForegroundColor Green
    Write-Host ''
    Write-Host 'On the tablet (PowerShell, one line):' -ForegroundColor Cyan
    Write-Host "  irm $url -OutFile s.zip; Expand-Archive s.zip -DestinationPath scrt4 -Force; .\scrt4\install.ps1"
}
