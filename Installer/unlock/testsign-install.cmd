@echo off
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Run this script as Administrator.
  pause
  exit /b 1
)

bcdedit /enum {current} | findstr /i "testsigning" | findstr /i "Yes" >nul
if errorlevel 1 (
  echo [ERROR] Test signing is not active. Run testsign-prepare.cmd and reboot first.
  pause
  exit /b 1
)

sc query SbieDrv >nul 2>&1
if not errorlevel 1 (
  echo [ERROR] An SbieDrv service already exists. Uninstall the official Sandboxie first.
  pause
  exit /b 1
)

echo [1/4] Installing SbieDrv...
"%~dp0KmdUtil.exe" install SbieDrv "%~dp0SbieDrv.sys" type=kernel start=demand msgfile="%~dp0SbieMsg.dll" altitude=86900
if errorlevel 1 goto fail

echo [2/4] Installing SbieSvc...
"%~dp0KmdUtil.exe" install SbieSvc "%~dp0SbieSvc.exe" type=own start=auto msgfile="%~dp0SbieMsg.dll" display="Sandboxie Service" group=UIGroup
if errorlevel 1 goto fail
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SbieSvc" /v PreferExternalManifest /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SbieDrv\Parameters" /v AllowOutdatedOffsets /t REG_DWORD /d 1 /f >nul 2>&1

echo [3/4] Starting SbieSvc (this loads SbieDrv)...
"%~dp0KmdUtil.exe" start SbieSvc
if errorlevel 1 goto fail

echo [4/4] Checking driver...
timeout /t 5 >nul
sc query SbieDrv | findstr /i "RUNNING" >nul
if errorlevel 1 (
  echo [WARN] SbieDrv does not report RUNNING yet. Check Event Viewer or retry after a few seconds.
)

echo.
echo [OK] Installation finished. Starting SandMan...
start "" "%~dp0SandMan.exe"
pause
exit /b 0

:fail
echo [ERROR] Installation failed. See the messages above.
pause
exit /b 1
