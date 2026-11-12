@echo off
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Run this script as Administrator.
  pause
  exit /b 1
)

echo [1/3] Checking Secure Boot...
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { if (Confirm-SecureBootUEFI) { exit 1 } } catch { }; exit 0"
if errorlevel 1 (
  echo [ERROR] Secure Boot is enabled. Disable Secure Boot in the VM firmware, then run again.
  pause
  exit /b 1
)

echo [2/3] Importing test certificate...
certutil -addstore -f Root "%~dp0sbie-test.cer" >nul
if errorlevel 1 goto fail
certutil -addstore -f TrustedPublisher "%~dp0sbie-test.cer" >nul
if errorlevel 1 goto fail

echo [3/3] Enabling test signing...
bcdedit /set testsigning on >nul
if errorlevel 1 goto fail

echo.
echo [OK] Test certificate installed and test signing enabled.
echo      Reboot the VM now, then run testsign-install.cmd as Administrator.
pause
exit /b 0

:fail
echo [ERROR] Preparation failed. See the messages above.
pause
exit /b 1
