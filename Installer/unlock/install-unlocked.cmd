@echo off
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Run this script as Administrator.
  pause
  exit /b 1
)

echo [1/5] Checking prerequisites...

powershell -NoProfile -ExecutionPolicy Bypass -Command "$s=(Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue).SecurityServicesRunning; if ($s -contains 2) { exit 1 }"
if errorlevel 1 (
  echo [ERROR] Memory Integrity / HVCI is ON. Disable it, reboot, then run again.
  pause
  exit /b 1
)

reg query "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v VulnerableDriverBlocklistEnable >nul 2>&1
if errorlevel 1 (
  echo [WARN] Vulnerable driver blocklist value is not set.
  echo        If the helper driver is blocked, run:
  echo        reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 0 /f
  echo        and reboot.
) else (
  for /f "tokens=3" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v VulnerableDriverBlocklistEnable ^| findstr /i VulnerableDriverBlocklistEnable') do set BL=%%A
  if /i not "%BL%"=="0x0" (
    echo [ERROR] Vulnerable driver blocklist is enabled. Disable it and reboot:
    echo   reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 0 /f
    pause
    exit /b 1
  )
)

sc query SbieDrv >nul 2>&1
if not errorlevel 1 (
  echo [ERROR] An SbieDrv service already exists. Uninstall the official Sandboxie first.
  pause
  exit /b 1
)

echo [2/5] Installing SbieDrv...
"%~dp0KmdUtil.exe" install SbieDrv "%~dp0SbieDrv.sys" type=kernel start=demand msgfile="%~dp0SbieMsg.dll" altitude=86900
if errorlevel 1 goto fail

echo [3/5] Installing SbieSvc...
"%~dp0KmdUtil.exe" install SbieSvc "%~dp0SbieSvc.exe" type=own start=auto msgfile="%~dp0SbieMsg.dll" display="Sandboxie Service" group=UIGroup
if errorlevel 1 goto fail
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SbieSvc" /v PreferExternalManifest /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SbieDrv\Parameters" /v AllowOutdatedOffsets /t REG_DWORD /d 1 /f >nul 2>&1

echo [4/5] Starting SbieSvc (loads SbieDrv through the BYOVD loader)...
"%~dp0KmdUtil.exe" start SbieSvc
if errorlevel 1 goto fail
timeout /t 8 >nul
sc query SbieDrv | findstr /i "RUNNING" >nul
if errorlevel 1 (
  echo [WARN] SbieDrv is not RUNNING yet. Check:
  echo        "%~dp0SbieUnlock.log"
  echo        Event Viewer -^> CodeIntegrity / Service Control Manager
) else (
  echo [OK] SbieDrv is running.
)

echo [5/5] Starting SandMan...
start "" "%~dp0SandMan.exe"
pause
exit /b 0

:fail
echo [ERROR] Installation failed. See the messages above and SbieUnlock.log.
pause
exit /b 1
