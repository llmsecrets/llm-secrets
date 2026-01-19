# Output.ps1
# Formatted output helpers for scrt CLI
# NO EMOJIS - Plain ASCII text only per PowerShell best practices

function Write-ScrtSuccess {
    <#
    .SYNOPSIS
    Writes a success message in green with [OK] prefix.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-ScrtError {
    <#
    .SYNOPSIS
    Writes an error message in red with [ERROR] prefix.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Write-ScrtWarning {
    <#
    .SYNOPSIS
    Writes a warning message in yellow with [WARNING] prefix.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-ScrtInfo {
    <#
    .SYNOPSIS
    Writes an info message in cyan with [INFO] prefix.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-ScrtHeader {
    <#
    .SYNOPSIS
    Writes a section header.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Title
    )
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-ScrtTable {
    <#
    .SYNOPSIS
    Writes a simple key-value table.
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$Data,
        [int]$KeyWidth = 20
    )

    foreach ($key in $Data.Keys | Sort-Object) {
        $paddedKey = $key.PadRight($KeyWidth)
        Write-Host "  $paddedKey : " -NoNewline -ForegroundColor Gray
        Write-Host "$($Data[$key])" -ForegroundColor White
    }
}
