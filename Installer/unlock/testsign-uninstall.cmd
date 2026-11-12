@echo off
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Run this script as Administrator.
  pause
  exit /b 1
)

echo [1/4] Stopping Sandboxie...
taskkill /f /im SandMan.exe >nul 2>&1
"%~dp0KmdUtil.exe" scandll_silent
"%~dp0KmdUtil.exe" stop SbieSvc
"%~dp0KmdUtil.exe" stop SbieDrv

echo [2/4] Deleting services...
"%~dp0KmdUtil.exe" delete SbieSvc
"%~dp0KmdUtil.exe" delete SbieDrv

echo [3/4] Removing test certificate...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$s='CN=Sandboxie-Plus Unlocked Test'; Get-ChildItem Cert:\LocalMachine\Root, Cert:\LocalMachine\TrustedPublisher | Where-Object { $_.Subject -like '*Sandboxie-Plus Unlocked Test*' } | Remove-Item -Force"

echo [4/4] Disabling test signing...
bcdedit /set testsigning off >nul

echo.
echo [OK] Uninstalled. Reboot to leave test signing mode.
pause
