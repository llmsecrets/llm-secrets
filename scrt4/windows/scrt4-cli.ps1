# scrt4-cli.ps1 -- implementation of the scrt4 PowerShell client.
# Deliberately NOT named scrt4.ps1: on PATH a scrt4.ps1 would shadow the
# scrt4.cmd shim in PowerShell and hit the Restricted execution-policy block.
# Reached via scrt4.cmd (the PATH entry, which sets -ExecutionPolicy Bypass),
# or directly for dev: .\scrt4-cli.ps1 <command> [args]
Import-Module (Join-Path $PSScriptRoot 'scrt4\scrt4.psd1') -Force
exit (Invoke-Scrt4 @args)
