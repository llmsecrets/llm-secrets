# scrt.ps1
# Main entry point for scrt CLI
# EnvCrypto Secrets Management CLI

# Use $args to avoid PowerShell parameter binding issues with "--"
$AllArgs = $args

$ErrorActionPreference = "Stop"

# Get script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Import CLI module
$CliModulePath = Join-Path $ScriptDir "scrt cli\ScrtCli.psm1"
if (-not (Test-Path $CliModulePath)) {
    Write-Host "[ERROR] ScrtCli.psm1 not found at: $CliModulePath" -ForegroundColor Red
    exit 1
}

try {
    Import-Module $CliModulePath -Force
} catch {
    Write-Host "[ERROR] Failed to load scrt module: $_" -ForegroundColor Red
    exit 1
}

# Parse command (first argument)
$Command = if ($AllArgs.Count -gt 0) { $AllArgs[0] } else { "help" }
# Ensure Arguments is always an array (not a single string which would be indexed as chars)
if ($AllArgs.Count -gt 1) {
    $Arguments = @($AllArgs[1..($AllArgs.Count - 1)])
} else {
    $Arguments = @()
}

# Handle --help and -h as first argument
if ($Command -eq "--help" -or $Command -eq "-h") {
    $Command = "help"
    $Arguments = @()
}

# Parse arguments for flags
$Force = $false
$VerboseFlag = $false
$Keep = $false
$Preview = $false
$MasterKey = $false
$Mode = ""
$RemainingArgs = @()
$FoundDoubleDash = $false

for ($i = 0; $i -lt $Arguments.Count; $i++) {
    $arg = $Arguments[$i]

    # If we found --, everything after goes to RemainingArgs
    if ($FoundDoubleDash) {
        $RemainingArgs += $arg
        continue
    }

    switch ($arg) {
        "--force" { $Force = $true }
        "-f" { $Force = $true }
        "--verbose" { $VerboseFlag = $true }
        "-v" { $VerboseFlag = $true }
        "--keep" { $Keep = $true }
        "--preview" { $Preview = $true }
        "--master-key" { $MasterKey = $true }
        "--mode" {
            if ($i + 1 -lt $Arguments.Count) {
                $Mode = $Arguments[$i + 1]
                $i++  # Skip next argument
            }
        }
        "--help" {
            $Command = "help"
        }
        "-h" {
            $Command = "help"
        }
        "--" {
            $FoundDoubleDash = $true
        }
        default {
            $RemainingArgs += $arg
        }
    }
}

# Log the command invocation
Write-ScrtLog -Message "CLI invoked: scrt $Command $($Arguments -join ' ')"

# Dispatch to appropriate command
try {
    switch ($Command.ToLower()) {
        "help" {
            if ($RemainingArgs.Count -gt 0) {
                Invoke-ScrtHelp -Command $RemainingArgs[0]
            } else {
                Invoke-ScrtHelp
            }
        }

        "version" {
            Invoke-ScrtVersion
        }

        "status" {
            Invoke-ScrtStatus
        }

        "auth" {
            $result = Invoke-ScrtAuth
            if (-not $result) { exit 1 }
        }

        "logout" {
            $result = Invoke-ScrtLogout
            if (-not $result) { exit 1 }
        }

        "list" {
            $result = Invoke-ScrtList -Verbose:$VerboseFlag
            if (-not $result) { exit 1 }
        }

        "encrypt" {
            $result = Invoke-ScrtEncrypt -Force:$Force -Keep:$Keep
            if (-not $result) { exit 1 }
        }

        "decrypt" {
            $result = Invoke-ScrtDecrypt -Preview:$Preview -MasterKey:$MasterKey
            if (-not $result) { exit 1 }
        }

        "init" {
            $result = Invoke-ScrtInit -Mode $Mode -Force:$Force
            if (-not $result) { exit 1 }
        }

        "run" {
            if ($RemainingArgs.Count -eq 0) {
                Write-ScrtError "No command specified. Usage: scrt run -- <command>"
                exit 4
            }
            Invoke-ScrtRun -Command $RemainingArgs
        }

        "view" {
            $secretName = if ($RemainingArgs.Count -gt 0) { $RemainingArgs[0] } else { "" }
            $result = Invoke-ScrtView -Secret $secretName -NoClear:$true
            if (-not $result) { exit 1 }
        }

        "setup" {
            $envPath = if ($RemainingArgs.Count -gt 0) { $RemainingArgs[0] } else { "" }
            $result = Invoke-ScrtSetup -EnvPath $envPath
            if (-not $result) { exit 1 }
        }

        default {
            Write-ScrtError "Unknown command: $Command"
            Write-Host ""
            Write-Host "Run 'scrt help' for available commands." -ForegroundColor Gray
            exit 4
        }
    }
} catch {
    Write-ScrtLog -Message "Error: $_" -Level "ERROR"
    Write-ScrtError "$_"
    exit 1
}

exit 0
