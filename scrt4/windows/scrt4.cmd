@echo off
rem The ONLY entry named `scrt4` on PATH. A .cmd is immune to PowerShell's
rem execution policy, and launches the client with -ExecutionPolicy Bypass,
rem so `scrt4 <cmd>` works in cmd.exe AND PowerShell on any Windows machine
rem with no policy change. The implementation is scrt4-cli.ps1 (NOT scrt4.ps1
rem — a top-level scrt4.ps1 would shadow this shim in PowerShell and hit the
rem Restricted-policy block).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scrt4-cli.ps1" %*
exit /b %ERRORLEVEL%
