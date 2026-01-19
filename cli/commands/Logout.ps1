# Logout.ps1
# scrt logout command

function Invoke-ScrtLogout {
    <#
    .SYNOPSIS
    Ends the current session.
    #>

    Write-ScrtLogOperation -Operation "logout"

    Write-Host ""
    Write-Host "scrt logout" -ForegroundColor Cyan
    Write-Host ""

    # Check if there's an active session
    $existingSession = Get-SessionKey
    if (-not $existingSession) {
        Write-ScrtInfo "No active session to logout from."
        Write-ScrtLogResult -Operation "logout" -Success $true -Details "No active session"
        return $true
    }

    # Remove session
    Remove-SessionKey

    Write-Host ""
    Write-ScrtSuccess "Session ended. You have been logged out."
    Write-Host ""
    Write-Host "Run 'scrt auth' to start a new session." -ForegroundColor Gray
    Write-Host ""

    Write-ScrtLogResult -Operation "logout" -Success $true
    return $true
}
