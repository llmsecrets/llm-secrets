# Status.ps1
# scrt status command

function Invoke-ScrtStatus {
    <#
    .SYNOPSIS
    Displays current session and configuration status.
    #>

    Write-ScrtLogOperation -Operation "status"

    Write-Host ""
    Write-Host "scrt status" -ForegroundColor Cyan
    Write-Host ""

    # Get settings
    $settings = Get-Settings

    # Session status
    Write-Host "SESSION:" -ForegroundColor Yellow
    $sessionKey = Get-SessionKey
    if ($sessionKey) {
        $cred = Get-SecureCredential -Target "EnvCrypto_SessionKey"
        if ($cred -and $cred.Metadata) {
            $createdAt = [DateTime]::Parse($cred.Metadata.CreatedAt)
            $expiresAt = [DateTime]::Parse($cred.Metadata.ExpiresAt)
            $now = Get-Date
            $timeRemaining = $expiresAt - $now

            $hoursRemaining = [Math]::Floor($timeRemaining.TotalHours)
            $minutesRemaining = [Math]::Floor($timeRemaining.TotalMinutes % 60)

            Write-Host "  Status:     " -NoNewline -ForegroundColor Gray
            Write-Host "Active" -ForegroundColor Green
            Write-Host "  Created:    $($createdAt.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
            Write-Host "  Expires:    $($expiresAt.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
            Write-Host "  Remaining:  ${hoursRemaining}h ${minutesRemaining}m" -ForegroundColor Cyan

            if ($timeRemaining.TotalMinutes -lt 60) {
                Write-Host ""
                Write-ScrtWarning "Session expiring soon. Run 'scrt auth' to refresh."
            }
        }
    } else {
        Write-Host "  Status:     " -NoNewline -ForegroundColor Gray
        Write-Host "No active session" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Run 'scrt auth' to authenticate." -ForegroundColor Yellow
    }

    Write-Host ""

    # Security mode
    Write-Host "CONFIGURATION:" -ForegroundColor Yellow
    Write-Host "  Security Mode:  $($settings.securityMode)" -ForegroundColor Gray

    if ($settings.securityMode -eq "simple") {
        $hasDpapiKey = Test-DpapiMasterKey
        Write-Host "  Master Key:     " -NoNewline -ForegroundColor Gray
        if ($hasDpapiKey) {
            Write-Host "DPAPI (configured)" -ForegroundColor Green
        } else {
            Write-Host "Not configured" -ForegroundColor Red
        }
    } else {
        $hasKeePass = Test-KeePassDatabase
        Write-Host "  KeePass DB:     " -NoNewline -ForegroundColor Gray
        if ($hasKeePass) {
            Write-Host "Configured" -ForegroundColor Green
        } else {
            Write-Host "Not configured" -ForegroundColor Red
        }
    }

    Write-Host ""

    # Files status
    Write-Host "FILES:" -ForegroundColor Yellow

    # Find the Scrt root directory
    $scrtRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $envPath = Join-Path $scrtRoot ".env"
    $envEncPath = Join-Path $scrtRoot ".env.encrypted"

    Write-Host "  .env:           " -NoNewline -ForegroundColor Gray
    if (Test-Path $envPath) {
        $envSize = (Get-Item $envPath).Length
        Write-Host "Present ($envSize bytes) - PLAINTEXT!" -ForegroundColor Yellow
    } else {
        Write-Host "Not present (secure)" -ForegroundColor Green
    }

    Write-Host "  .env.encrypted: " -NoNewline -ForegroundColor Gray
    if (Test-Path $envEncPath) {
        $encSize = (Get-Item $envEncPath).Length
        Write-Host "Present ($encSize bytes)" -ForegroundColor Green
    } else {
        Write-Host "Not present" -ForegroundColor Red
    }

    Write-Host ""

    Write-ScrtLogResult -Operation "status" -Success $true
}
