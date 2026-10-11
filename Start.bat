@echo off
setlocal
rem ===================================================================
rem  Windows 11 Security Optimizer - one-click launcher
rem  Double-click this file. It will:
rem    1. Ask for administrator rights (needed to apply fixes).
rem    2. Launch the GUI with PowerShell in STA mode.
rem  No installation, no .exe, no SmartScreen quarantine.
rem ===================================================================

rem --- Are we already elevated? (net session only works as admin) ---
net session >nul 2>&1
if %errorlevel% EQU 0 goto :run

rem --- Not elevated: relaunch this .bat as administrator ---
echo Requesting administrator rights...
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
exit /b

:run
set "PS1=%~dp0src\Optimizer.ps1"
if not exist "%PS1%" (
  echo.
  echo ERROR: Could not find "%PS1%".
  echo Make sure you extracted the whole folder, keeping Start.bat next to the "src" folder.
  echo.
  pause
  exit /b 1
)

rem --- Launch the GUI (STA is required for WPF) ---
powershell -NoProfile -ExecutionPolicy Bypass -STA -File "%PS1%"
if %errorlevel% NEQ 0 (
  echo.
  echo The optimizer exited with an error. See the log window above.
  pause
)
exit /b
