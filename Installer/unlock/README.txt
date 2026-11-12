Sandboxie-Plus Unlocked (test-signing build)
=============================================

This package is a self-compiled, fully unlocked build for TESTING ONLY.

Prerequisites
-------------
- Windows 10/11 x64 VM (tested target: Windows 10 22H2).
- Secure Boot must be OFF (test signing is ignored when Secure Boot is on).
- Uninstall any official Sandboxie-Plus installation first.

Steps
-----
1. Extract this zip to a folder, e.g. C:\SbieUnlocked.
2. Run testsign-prepare.cmd as Administrator.
   - imports sbie-test.cer into Root + TrustedPublisher
   - enables test signing
3. Reboot the VM.
4. Run testsign-install.cmd as Administrator.
   - installs SbieDrv (demand start) and SbieSvc (auto start)
   - starts SbieSvc, which loads the driver
   - launches SandMan
5. Check: SandMan connects, certificate state is active/ETERNAL,
   security/encryption/network/desktop features are available,
   and sandboxed processes are not killed after 5 minutes.

Uninstall
---------
Run testsign-uninstall.cmd as Administrator, then reboot.
It stops/deletes the services, removes the test certificate and disables test signing.

Notes
-----
- This build disables online updates on purpose: an official update would
  replace the unlocked binaries.
- The test certificate and private key are generated per CI build; the .cer
  in this package is the matching public certificate.
- Do not use this package on a production machine.
