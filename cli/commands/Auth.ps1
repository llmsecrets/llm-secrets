# Auth.ps1
# scrt auth command

function Invoke-ScrtAuth {
    <#
    .SYNOPSIS
    Authenticates with Windows Hello and creates a session.
    #>

    Write-ScrtLogOperation -Operation "auth"

    Write-Host ""
    Write-Host "scrt auth" -ForegroundColor Cyan
    Write-Host ""

    # Check if already have a valid session
    $existingSession = Get-SessionKey
    if ($existingSession) {
        Write-ScrtInfo "Active session exists. Creating new session..."
    }

    # Get settings to determine security mode
    $settings = Get-Settings

    if ($settings.securityMode -eq "simple") {
        Write-Host "Security Mode: Simple (Windows Hello only)" -ForegroundColor Gray
    } else {
        Write-Host "Security Mode: Advanced (Windows Hello + KeePass)" -ForegroundColor Gray
    }
    Write-Host ""

    # Check prerequisites
    if ($settings.securityMode -eq "simple") {
        if (-not (Test-DpapiMasterKey)) {
            Write-ScrtError "DPAPI master key not found. Run 'scrt init' first."
            Write-ScrtLogResult -Operation "auth" -Success $false -Details "DPAPI key not found"
            return $false
        }
    } else {
        if (-not (Test-KeePassDatabase)) {
            Write-ScrtError "KeePass database not found. Run 'scrt init' first."
            Write-ScrtLogResult -Operation "auth" -Success $false -Details "KeePass DB not found"
            return $false
        }
    }

    # Perform authentication
    $result = New-SessionKey

    if ($result) {
        Write-Host ""
        Write-ScrtSuccess "Session created. Valid for 2 hours."
        Write-Host ""
        Write-Host "You can now use: scrt list, scrt encrypt, scrt decrypt, scrt run" -ForegroundColor Gray
        Write-ScrtLogResult -Operation "auth" -Success $true
        return $true
    } else {
        Write-Host ""
        Write-ScrtError "Authentication failed."
        Write-ScrtLogResult -Operation "auth" -Success $false -Details "Authentication failed"
        return $false
    }
}
