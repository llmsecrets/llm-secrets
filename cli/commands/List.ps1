# List.ps1
# scrt list command

function Invoke-ScrtList {
    <#
    .SYNOPSIS
    Lists secret names from .env.encrypted (never shows values).
    #>
    param(
        [switch]$Verbose
    )

    Write-ScrtLogOperation -Operation "list" -Details "verbose=$Verbose"

    Write-Host ""
    Write-Host "scrt list" -ForegroundColor Cyan
    Write-Host ""

    # Check for valid session
    $sessionKey = Get-SessionKey
    if (-not $sessionKey) {
        Write-ScrtError "No active session. Run 'scrt auth' first."
        Write-ScrtLogResult -Operation "list" -Success $false -Details "No session"
        exit 2
    }

    # Find encrypted file
    $scrtRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $envEncPath = Join-Path $scrtRoot ".env.encrypted"

    if (-not (Test-Path $envEncPath)) {
        Write-ScrtError ".env.encrypted not found."
        Write-Host "Run 'scrt encrypt' to create it from .env" -ForegroundColor Gray
        Write-ScrtLogResult -Operation "list" -Success $false -Details "File not found"
        exit 3
    }

    # Decrypt in-memory
    Write-Host "Decrypting secrets in-memory..." -ForegroundColor Gray
    $envContent = Unprotect-EnvFile -InputPath $envEncPath -InMemory

    if (-not $envContent) {
        Write-ScrtError "Failed to decrypt .env.encrypted"
        Write-ScrtLogResult -Operation "list" -Success $false -Details "Decryption failed"
        exit 1
    }

    # Parse secret names
    $secrets = @{}
    $comments = 0
    $lines = $envContent.Split("`n")

    foreach ($line in $lines) {
        $trimmed = $line.Trim()

        # Skip empty lines
        if (-not $trimmed) { continue }

        # Count comments
        if ($trimmed.StartsWith("#")) {
            $comments++
            continue
        }

        # Parse key=value
        if ($trimmed -match '^([^=]+)=(.*)$') {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            $secrets[$key] = $value.Length
        }
    }

    # Display results
    Write-Host ""
    Write-Host "SECRETS ($($secrets.Count) found):" -ForegroundColor Yellow
    Write-Host ""

    if ($Verbose) {
        # Show names with value lengths
        $maxKeyLength = ($secrets.Keys | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
        if ($maxKeyLength -lt 20) { $maxKeyLength = 20 }

        foreach ($key in $secrets.Keys | Sort-Object) {
            $paddedKey = $key.PadRight($maxKeyLength)
            $valueLength = $secrets[$key]
            Write-Host "  $paddedKey  " -NoNewline -ForegroundColor White
            Write-Host "($valueLength chars)" -ForegroundColor Gray
        }
    } else {
        # Show names only
        foreach ($key in $secrets.Keys | Sort-Object) {
            Write-Host "  $key" -ForegroundColor White
        }
    }

    Write-Host ""
    Write-Host "Total: $($secrets.Count) secrets, $comments comment lines" -ForegroundColor Gray
    Write-Host ""

    # NEVER log secret values - only count
    Write-ScrtLogResult -Operation "list" -Success $true -Details "Listed $($secrets.Count) secrets"

    # Clear sensitive data from memory
    $envContent = $null
    [System.GC]::Collect()

    return $true
}
