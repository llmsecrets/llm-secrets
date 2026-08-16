# bootstrap.ps1 -- served at https://dl.llmsecrets.com/scrt4
#
#   irm https://dl.llmsecrets.com/scrt4 | iex
#
# Downloads the prebuilt scrt4 Windows bundle, VERIFIES ITS SHA256 against the
# published checksums, unpacks it, and installs. The target machine needs
# nothing pre-installed: no Rust, no MSVC, no vcpkg, no OpenSSL, no Python.
$ErrorActionPreference = 'Stop'

$base = 'https://dl.llmsecrets.com/scrt4'
$zipName = 'scrt4-windows-latest.zip'
$tmp = Join-Path $env:TEMP ('scrt4-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

try {
    Write-Host 'scrt4 -- downloading...' -ForegroundColor Cyan
    $zip = Join-Path $tmp $zipName
    Invoke-WebRequest "$base/$zipName" -OutFile $zip -UseBasicParsing

    # Verify before executing anything out of the archive.
    Write-Host 'Verifying checksum...' -ForegroundColor Cyan
    $sums = (Invoke-WebRequest "$base/SHA256SUMS.txt" -UseBasicParsing).Content
    $want = ($sums -split "`n" | Where-Object { $_ -match [regex]::Escape($zipName) } |
             Select-Object -First 1) -split '\s+' | Select-Object -First 1
    $got = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
    if (-not $want) { throw "No checksum published for $zipName" }
    if ($got -ne $want.ToLower()) {
        throw "CHECKSUM MISMATCH`n  expected $want`n  got      $got`nRefusing to install."
    }
    Write-Host "  ok  $got" -ForegroundColor Green

    Expand-Archive -Path $zip -DestinationPath (Join-Path $tmp 'pkg') -Force

    # Run the packaged installer through a CHILD PowerShell with the execution
    # policy explicitly bypassed.
    #
    # Why this dance: piping THIS bootstrap to `iex` slips past execution
    # policy because iex runs a *string*, and execution policy only governs
    # script *files*. But the installer inside the zip is a file, so a bare
    # `& install.ps1` is subject to policy -- and on a default Windows laptop
    # that policy is Restricted, which is exactly the "running scripts is
    # disabled on this system" error users were hitting. Expand-Archive also
    # stamps the extracted file with the Mark-of-the-Web, which RemoteSigned
    # would block too. `-ExecutionPolicy Bypass` on a child process clears
    # both, without changing anything on the user's machine. We keep it a real
    # `-File` call (not `iex`) so the installer's $PSScriptRoot still resolves
    # to the package dir. Re-invoke the SAME host so this works whether the
    # user ran the one-liner in Windows PowerShell 5.1 or PowerShell 7.
    $installPs1 = Join-Path $tmp 'pkg\install.ps1'
    $psExe = (Get-Process -Id $PID).Path
    if (-not $psExe) { $psExe = 'powershell.exe' }
    & $psExe -NoProfile -ExecutionPolicy Bypass -File $installPs1
    if ($LASTEXITCODE -ne 0) { throw "installer exited with code $LASTEXITCODE" }
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
