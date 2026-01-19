# Version.ps1
# scrt version command

$script:ScrtVersion = "1.0.0"
$script:ScrtBuildDate = "2025-01-17"

function Invoke-ScrtVersion {
    <#
    .SYNOPSIS
    Displays version information for scrt CLI.
    #>

    Write-ScrtLog -Message "Version requested"

    Write-Host ""
    Write-Host "scrt - EnvCrypto Secrets Management CLI" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Version:    $script:ScrtVersion" -ForegroundColor White
    Write-Host "  Build Date: $script:ScrtBuildDate" -ForegroundColor Gray
    Write-Host "  PowerShell: $($PSVersionTable.PSVersion)" -ForegroundColor Gray
    $platform = if ($PSVersionTable.Platform) { $PSVersionTable.Platform } else { "Windows" }
    Write-Host "  Platform:   $platform" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Components:" -ForegroundColor Yellow
    Write-Host "  EnvCrypto.psm1      AES-256 encryption, session management"
    Write-Host "  WindowsHelloAuth    Biometric/PIN authentication"
    Write-Host ""
}

function Get-ScrtVersion {
    <#
    .SYNOPSIS
    Returns the version string.
    #>
    return $script:ScrtVersion
}
