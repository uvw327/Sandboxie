/*
 * dse_locate.h - locate ci.dll!g_CiOptions from the user-mode mapped image.
 *
 * The scanner is a port of hfiref0x/KDU (Source/Hamakaze/dsefix.cpp, MIT)
 * and the Hacker Disassembler Engine (hde64, BSD-3-Clause).
 */
#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns TRUE and stores the kernel VA of g_CiOptions in *outVa.
 * On failure returns FALSE and leaves a human readable reason in
 * g_dse_locate_error. */
BOOL LocateCiOptions(HMODULE mappedBase, ULONG_PTR loadedBase, ULONG_PTR* outVa);

extern char g_dse_locate_error[256];

#ifdef __cplusplus
}
#endif
