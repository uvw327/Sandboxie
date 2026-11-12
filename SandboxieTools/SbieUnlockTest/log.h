/*
 * log.h - simple file logger for the unlock thread
 *
 * Writes to version_hook.log next to the DLL.
 * All modules include this and use LOGI / LOGE / LOGW macros.
 */
#ifndef LOG_H
#define LOG_H

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

static char g_log_path[MAX_PATH] = {0};

/* The log is append-only and grows forever otherwise: every SandMan start
 * adds ~4 KB.  One previous file is kept, the older one is overwritten. */
#define LOG_MAX_BYTES (1024u * 1024u)

/* Defined below; log_init needs it for the ANSI-path warning. */
static void log_write(const char *level, const char *fmt, ...);

static void log_rotate(void)
{
    HANDLE hFile = CreateFileA(g_log_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    DWORD size = GetFileSize(hFile, NULL);
    CloseHandle(hFile);
    if (size == INVALID_FILE_SIZE || size < LOG_MAX_BYTES) return;

    char old_path[MAX_PATH];
    strcpy_s(old_path, MAX_PATH, g_log_path);
    char *dot = strrchr(old_path, '.');
    if (dot) strcpy_s(dot, MAX_PATH - (dot - old_path), ".old.log");
    MoveFileExA(g_log_path, old_path, MOVEFILE_REPLACE_EXISTING);
}

/* Is the log file creatable where it should live?  The install directory is
 * admin-only and SandMan.exe is asInvoker, so an unelevated host (a plain
 * double-click) cannot write next to the DLL - without a fallback the hook
 * would look like it never ran at all. */
static BOOL log_path_writable(void)
{
    HANDLE h = CreateFileA(g_log_path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    CloseHandle(h);
    return TRUE;
}

static void log_init(void)
{
    if (g_log_path[0]) return;
    GetModuleFileNameA(NULL, g_log_path, MAX_PATH);
    char *p = strrchr(g_log_path, '\\');
    if (p) {
        strcpy_s(p + 1, MAX_PATH - (p + 1 - g_log_path), "SbieUnlockTest.log");
    } else {
        strcpy_s(g_log_path, MAX_PATH, "SbieUnlockTest.log");
    }

    /* Fall back to %TEMP% when the binary sits in a read-only location. */
    BOOL ansi_ok = strchr(g_log_path, '?') == NULL;
    if (!ansi_ok || !log_path_writable()) {
        char tmp[MAX_PATH];
        DWORD n = GetTempPathA(MAX_PATH, tmp);
        if (n && n < MAX_PATH) {
            _snprintf_s(g_log_path, MAX_PATH, _TRUNCATE, "%sSbieUnlockTest.log", tmp);
        }
    }
    log_rotate();
}

static void log_write(const char *level, const char *fmt, ...)
{
    log_init();

    HANDLE hFile = CreateFileA(g_log_path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    char ts[32];
    wsprintfA(ts, "%02d:%02d:%02d.%03d ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    char prefix[16];
    wsprintfA(prefix, "[%s] ", level);

    char msg[1024];
    va_list args;
    va_start(args, fmt);
    _vsnprintf_s(msg, sizeof(msg), _TRUNCATE, fmt, args);
    va_end(args);

    char line[1200];
    int len = _snprintf_s(line, sizeof(line), _TRUNCATE, "%s%s%s\r\n", ts, prefix, msg);
    if (len < 0) len = 0;

    DWORD written = 0;
    if (len > 0) WriteFile(hFile, line, (DWORD)len, &written, NULL);
    /* Crash-time diagnostics matter: a bugcheck does not flush the cache,
     * so the lines written just before it would be lost. */
    FlushFileBuffers(hFile);
    CloseHandle(hFile);
}

#define LOGI(...) log_write("INFO", __VA_ARGS__)
#define LOGE(...) log_write("ERROR", __VA_ARGS__)
#define LOGW(...) log_write("WARN", __VA_ARGS__)

#endif /* LOG_H */
