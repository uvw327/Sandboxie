@echo off
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Run this script as Administrator.
  pause
  exit /b 1
)

echo [1/3] Stopping Sandboxie...
taskkill /f /im SandMan.exe >nul 2>&1
"%~dp0KmdUtil.exe" scandll_silent
"%~dp0KmdUtil.exe" stop SbieSvc
"%~dp0KmdUtil.exe" stop SbieDrv

echo [2/3] Deleting services...
"%~dp0KmdUtil.exe" delete SbieSvc
"%~dp0KmdUtil.exe" delete SbieDrv

echo [3/3] Done.
echo Reboot to unload the helper driver from memory.
pause
