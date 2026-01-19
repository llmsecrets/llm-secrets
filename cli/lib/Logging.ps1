# Logging.ps1
# File-based logging for scrt CLI
# Per QA rules: log before/after operations with timestamps

# Script-level variables
$script:LogPath = $null
$script:LogEnabled = $true

function Initialize-ScrtLogging {
    <#
    .SYNOPSIS
    Initializes the logging system.
    #>
    param(
        [string]$LogDirectory = ""
    )

    if ($LogDirectory -eq "") {
        # Default to logs folder in Scrt directory
        $scrtRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        $LogDirectory = Join-Path $scrtRoot "logs"
    }

    # Create logs directory if it doesn't exist
    if (-not (Test-Path $LogDirectory)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }

    $script:LogPath = Join-Path $LogDirectory "scrt.log"
}

function Write-ScrtLog {
    <#
    .SYNOPSIS
    Writes a timestamped entry to the log file.

    .DESCRIPTION
    Logs are written with format: [YYYY-MM-DD HH:mm:ss.fff] [LEVEL] Message
    NEVER logs secret values - only names and counts.

    .PARAMETER Message
    The message to log.

    .PARAMETER Level
    Log level: INFO, WARNING, ERROR, DEBUG
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("INFO", "WARNING", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )

    if (-not $script:LogEnabled) {
        return
    }

    # Initialize logging if not done
    if (-not $script:LogPath) {
        Initialize-ScrtLogging
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "[$timestamp] [$Level] $Message"

    try {
        Add-Content -Path $script:LogPath -Value $logEntry -Encoding UTF8
    } catch {
        # Silently fail - don't break CLI for logging issues
    }
}

function Write-ScrtLogOperation {
    <#
    .SYNOPSIS
    Logs the start of an operation.

    .PARAMETER Operation
    Name of the operation (e.g., "auth", "encrypt", "decrypt")

    .PARAMETER Details
    Optional details about the operation
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Operation,

        [string]$Details = ""
    )

    $message = ">>> $Operation"
    if ($Details) {
        $message += " - $Details"
    }
    Write-ScrtLog -Message $message -Level "INFO"
}

function Write-ScrtLogResult {
    <#
    .SYNOPSIS
    Logs the result of an operation.

    .PARAMETER Operation
    Name of the operation

    .PARAMETER Success
    Whether the operation succeeded

    .PARAMETER Details
    Optional result details
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Operation,

        [Parameter(Mandatory)]
        [bool]$Success,

        [string]$Details = ""
    )

    $status = if ($Success) { "SUCCESS" } else { "FAILED" }
    $message = "<<< $Operation - $status"
    if ($Details) {
        $message += " - $Details"
    }

    $level = if ($Success) { "INFO" } else { "ERROR" }
    Write-ScrtLog -Message $message -Level $level
}

function Get-ScrtLogPath {
    <#
    .SYNOPSIS
    Returns the current log file path.
    #>
    if (-not $script:LogPath) {
        Initialize-ScrtLogging
    }
    return $script:LogPath
}

function Disable-ScrtLogging {
    <#
    .SYNOPSIS
    Disables logging.
    #>
    $script:LogEnabled = $false
}

function Enable-ScrtLogging {
    <#
    .SYNOPSIS
    Enables logging.
    #>
    $script:LogEnabled = $true
}
