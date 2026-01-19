# View.ps1
# scrt view command - Authenticate and view secrets in one step

function Invoke-ScrtView {
    <#
    .SYNOPSIS
    Authenticates with Windows Hello and displays decrypted secrets.

    .DESCRIPTION
    Combines auth + decrypt in one command:
    1. Checks for active session, authenticates if needed
    2. Decrypts .env.encrypted in memory
    3. Displays secret values

    Secrets are never written to disk.

    .PARAMETER Secret
    Optional: View only a specific secret by name

    .PARAMETER NoClear
    Don't auto-clear the console after viewing

    .EXAMPLE
    scrt view
    scrt view --secret STRIPE_SECRET_KEY
    scrt view --no-clear
    #>
    param(
        [string]$Secret = "",
        [switch]$NoClear,
        [int]$ClearAfter = 30
    )

    Write-ScrtLogOperation -Operation "view" -Details "secret=$Secret, noClear=$NoClear"

    Write-ScrtHeader "scrt view"

    # Step 1: Check/create session
    $sessionKey = Get-SessionKey
    if (-not $sessionKey) {
        Write-ScrtInfo "Authenticating with Windows Hello..."
        $authResult = New-SessionKey
        if (-not $authResult) {
            Write-ScrtError "Windows Hello authentication failed."
            Write-ScrtLogResult -Operation "view" -Success $false -Details "Auth failed"
            return $false
        }
    } else {
        Write-ScrtInfo "Using existing session."
    }

    # Step 2: Find encrypted file - check multiple locations, use most recent
    $possiblePaths = @()

    # Add paths relative to script location
    $possiblePaths += Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) ".env.encrypted"  # Keep Scrt/
    $possiblePaths += Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) ".env.encrypted"  # Scrt/
    $possiblePaths += Join-Path (Get-Location) ".env.encrypted"  # Current directory

    # Add from environment variable if set
    if ($env:KEEP_SCRT_PATH) {
        $possiblePaths += Join-Path $env:KEEP_SCRT_PATH ".env.encrypted"
    }

    # Find all existing files and pick the most recently modified
    $existingFiles = @()
    foreach ($path in $possiblePaths) {
        if ($path -and (Test-Path $path)) {
            $existingFiles += Get-Item $path
        }
    }
    $existingFiles = $existingFiles | Sort-Object LastWriteTime -Descending

    if ($existingFiles.Count -eq 0) {
        Write-ScrtError ".env.encrypted not found in any expected location."
        Write-ScrtLogResult -Operation "view" -Success $false -Details "File not found"
        return $false
    }

    $envEncPath = $existingFiles[0].FullName
    Write-ScrtInfo "Using: $envEncPath"

    # Step 3: Decrypt in-memory
    Write-ScrtInfo "Decrypting secrets..."
    $envContent = Unprotect-EnvFile -InputPath $envEncPath -InMemory

    if (-not $envContent) {
        Write-ScrtError "Failed to decrypt .env.encrypted"
        Write-ScrtLogResult -Operation "view" -Success $false -Details "Decrypt failed"
        return $false
    }

    # Step 4: Parse secrets
    $secrets = @{}
    $lines = $envContent.Split("`n")

    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }
        if ($trimmed.StartsWith("#")) { continue }

        if ($trimmed -match '^([^=]+)=(.*)$') {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            # Remove surrounding quotes if present
            if ($value -match '^"(.*)"$' -or $value -match "^'(.*)'$") {
                $value = $matches[1]
            }
            $secrets[$key] = $value
        }
    }

    # Clear content from memory
    $envContent = $null

    # Step 5: Display secrets
    Write-Host ""
    Write-Host "========== SECRET VALUES ==========" -ForegroundColor Red
    Write-Host ""

    if ($Secret) {
        # Show specific secret
        if ($secrets.ContainsKey($Secret)) {
            Write-Host "$Secret = " -NoNewline -ForegroundColor Yellow
            Write-Host $secrets[$Secret] -ForegroundColor White
        } else {
            Write-ScrtError "Secret '$Secret' not found."
            Write-Host ""
            Write-Host "Available secrets:" -ForegroundColor Gray
            foreach ($key in $secrets.Keys | Sort-Object) {
                Write-Host "  - $key" -ForegroundColor Gray
            }
            Write-ScrtLogResult -Operation "view" -Success $false -Details "Secret not found: $Secret"
            return $false
        }
    } else {
        # Show all secrets
        foreach ($key in $secrets.Keys | Sort-Object) {
            Write-Host "$key = " -NoNewline -ForegroundColor Yellow
            Write-Host $secrets[$key] -ForegroundColor White
        }
    }

    Write-Host ""
    Write-Host "===================================" -ForegroundColor Red
    Write-Host ""

    $secretCount = $secrets.Keys.Count
    Write-ScrtSuccess "Displayed $secretCount secret(s)"

    # Clear secrets from memory
    $secrets = $null
    [System.GC]::Collect()

    Write-ScrtLogResult -Operation "view" -Success $true -Details "Displayed $secretCount secrets"
    return $true
}
