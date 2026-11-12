#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Prepare the environment for loading the self-built SbieDrv.sys.
 *
 * - If test signing is on, returns TRUE without touching the kernel.
 * - Otherwise loads the embedded dbutil helper, locates ci.dll!g_CiOptions,
 *   and disables DSE (writes 0), verifying the write.
 * - Returns FALSE on any unsafe/failed condition; SbieUnlockLastError()
 *   then contains a human readable reason.
 */
BOOL SbieUnlockPrepareDriverLoad(void);

/*
 * Restore the original DSE value (if it was changed) and release the helper.
 * Safe to call when Prepare failed or was never called.
 */
void SbieUnlockFinishDriverLoad(void);

/* Reason for the last Prepare failure (never NULL). */
const char* SbieUnlockLastError(void);

#ifdef __cplusplus
}
#endif
