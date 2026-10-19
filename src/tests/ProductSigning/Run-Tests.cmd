@echo off
setlocal

where pwsh.exe >nul 2>nul
if errorlevel 1 (
    echo ERROR: PowerShell 7.6 or later is required and pwsh.exe was not found.
    exit /b 1
)

pwsh.exe -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0Invoke-ProductSigningTests.ps1" %*
exit /b %errorlevel%
