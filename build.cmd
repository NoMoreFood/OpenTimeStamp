@ECHO OFF
SETLOCAL
SET COPYCMD=/Y

REM Let Windows PowerShell initialize its own module paths.
SET PSMODULEPATH=

"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
    -File "%~dp0tools\build\Build.ps1" -SkipTests %*
EXIT /B %ERRORLEVEL%
