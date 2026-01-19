# Run.ps1
# scrt run command - Run command with secrets injected

function Invoke-ScrtRun {
    <#
    .SYNOPSIS
    Runs a command with decrypted secrets injected as environment variables.
    #>
    param(
        [Parameter(Mandatory)]
        [string[]]$Command
    )

    $cmdString = $Command -join " "
    Write-ScrtLogOperation -Operation "run" -Details "command=$cmdString"

    # Check for valid session
    $sessionKey = Get-SessionKey
    if (-not $sessionKey) {
        Write-ScrtError "No active session. Run 'scrt auth' first."
        Write-ScrtLogResult -Operation "run" -Success $false -Details "No session"
        exit 2
    }

    # Find encrypted file
    $scrtRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $envEncPath = Join-Path $scrtRoot ".env.encrypted"

    if (-not (Test-Path $envEncPath)) {
        Write-ScrtError ".env.encrypted not found."
        Write-ScrtLogResult -Operation "run" -Success $false -Details "File not found"
        exit 3
    }

    # Decrypt in-memory
    Write-ScrtInfo "Loading secrets..."
    $envContent = Unprotect-EnvFile -InputPath $envEncPath -InMemory

    if (-not $envContent) {
        Write-ScrtError "Failed to decrypt secrets."
        Write-ScrtLogResult -Operation "run" -Success $false -Details "Decryption failed"
        exit 1
    }

    # Parse and inject secrets
    $secretCount = 0
    $lines = $envContent.Split("`n")

    foreach ($line in $lines) {
        $trimmed = $line.Trim()

        # Skip empty lines and comments
        if (-not $trimmed -or $trimmed.StartsWith("#")) { continue }

        # Parse key=value
        if ($trimmed -match '^([^=]+)=(.*)$') {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()

            # Set environment variable
            [Environment]::SetEnvironmentVariable($key, $value, "Process")
            $secretCount++
        }
    }

    # Clear decrypted content from memory
    $envContent = $null
    [System.GC]::Collect()

    Write-ScrtSuccess "Injected $secretCount secrets"
    Write-Host ""
    Write-ScrtInfo "Running: $cmdString"
    Write-Host ""

    # Execute the command
    try {
        # Determine how to run the command
        if ($Command.Count -eq 1) {
            # Single command - might be a path or command with args
            $parts = $Command[0].Split(" ", 2)
            $executable = $parts[0]
            $arguments = if ($parts.Count -gt 1) { $parts[1] } else { "" }

            if ($arguments) {
                $process = Start-Process -FilePath $executable -ArgumentList $arguments -NoNewWindow -Wait -PassThru
            } else {
                $process = Start-Process -FilePath $executable -NoNewWindow -Wait -PassThru
            }
            $exitCode = $process.ExitCode
        } else {
            # Multiple arguments passed
            $executable = $Command[0]
            $arguments = $Command[1..($Command.Count - 1)]

            $process = Start-Process -FilePath $executable -ArgumentList $arguments -NoNewWindow -Wait -PassThru
            $exitCode = $process.ExitCode
        }

        Write-Host ""
        if ($exitCode -eq 0) {
            Write-ScrtSuccess "Command completed successfully"
        } else {
            Write-ScrtWarning "Command exited with code: $exitCode"
        }

        Write-ScrtLogResult -Operation "run" -Success ($exitCode -eq 0) -Details "Exit code: $exitCode"
        exit $exitCode

    } catch {
        Write-Host ""
        Write-ScrtError "Failed to execute command: $_"
        Write-ScrtLogResult -Operation "run" -Success $false -Details "Execution failed: $_"
        exit 1
    }
}
