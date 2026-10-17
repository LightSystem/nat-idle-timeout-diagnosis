@echo off
setlocal
REM Windows launcher for ISP / NAT TCP idle-timeout diagnostic tool.
REM Uses Python 3 if available and arguments use --flags, or native PowerShell (no Python required).

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0diagnose.ps1" %*
set EXIT_CODE=%ERRORLEVEL%

REM If double-clicked in Explorer, keep the window open so the user can read the diagnosis
echo %CMDCMDLINE% | find /i "/c" >nul
if not errorlevel 1 (
    echo.
    pause
)
exit /b %EXIT_CODE%
