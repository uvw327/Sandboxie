Sandboxie-Plus Unlocked - self-compiled build
=============================================

This package is a self-compiled, fully unlocked build for TESTING ONLY.

There are two ways to load the self-built SbieDrv.sys:

A. BYOVD loader (recommended; Secure Boot can stay on)
------------------------------------------------------
Prerequisites:
- Memory Integrity / HVCI must be OFF.
- Microsoft Vulnerable Driver Blocklist must be OFF:
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 0 /f
  then reboot.
- No official Sandboxie installation.

Steps:
1. Extract this zip to a folder, e.g. C:\SbieUnlocked.
2. Run install-unlocked.cmd as Administrator.
   - installs SbieDrv (demand start) and SbieSvc (auto start)
   - starts SbieSvc, which patches DSE, loads SbieDrv and restores DSE
   - launches SandMan
3. If the driver does not start, read SbieUnlock.log next to SbieSvc.exe.

B. Test signing (development / validation)
------------------------------------------
Prerequisites:
- Secure Boot must be OFF (test signing is ignored when Secure Boot is on).
- Uninstall any official Sandboxie-Plus installation first.

Steps:
1. Extract this zip to a folder.
2. Run testsign-prepare.cmd as Administrator (imports sbie-test.cer,
   enables test signing), then reboot.
3. Run testsign-install.cmd as Administrator.

Uninstall
---------
- BYOVD build: run uninstall-unlocked.cmd as Administrator.
- Test-signing build: run testsign-uninstall.cmd as Administrator.
Then reboot.

Notes
-----
- Online updates are disabled on purpose: an official update would replace
  this unlocked build.
- The helper driver (dbutil_2_3.sys) stays loaded until reboot; the loader
  deletes its temporary service but does not stop a live driver.
- SbieUnlockTest.exe is a standalone probe for the BYOVD path (see Docs/06).
- Do not use this package on a production machine.
