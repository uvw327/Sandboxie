/*
 * dse_locate.cpp - locate ci.dll!g_CiOptions.
 *
 * Ported from hfiref0x/KDU (MIT), Source/Hamakaze/dsefix.cpp:
 *   - KDUValidateCiInitializeCode
 *   - KDUInstructionIsRipRelativeStore32 / related helpers
 *   - KDUQueryCiOptionsEx (RS3 and later path only)
 *
 * HDE64 (hde/hde64.c) is Copyright (c) 2008-2009 Vyacheslav Patkov,
 * BSD-3-Clause.
 */

#include "dse_locate.h"
#include "hde/hde64.h"

#include <windows.h>
#include <stdio.h>

char g_dse_locate_error[256] = {0};

static void set_error(const char* msg)
{
    _snprintf_s(g_dse_locate_error, sizeof(g_dse_locate_error), _TRUNCATE, "%s", msg);
}

static BOOL InstuctionHasRexPrefix(hde64s* hs, PBYTE code, BYTE rexMask, BYTE rexValue)
{
    BYTE rex;

    if (hs == NULL || code == NULL)
        return FALSE;
    if (hs->len != 3)
        return FALSE;

    rex = code[0];
    if ((rex & 0xF0) != 0x40)
        return FALSE;
    if ((rex & rexMask) != rexValue)
        return FALSE;
    return TRUE;
}

static BOOL InstructionIsRspStoreRax(hde64s* hs, PBYTE code)
{
    BYTE modrm;

    if (hs == NULL || code == NULL)
        return FALSE;
    if (code[0] != 0x48)
        return FALSE;
    if (hs->opcode != 0x89)
        return FALSE;
    if (!(hs->flags & F_MODRM))
        return FALSE;

    modrm = hs->modrm;

    if (hs->len == 5) {
        if ((modrm == 0x44) && (code[3] == 0x24))
            return TRUE;
    }
    if (hs->len == 8) {
        if ((modrm == 0x84) && (code[3] == 0x24))
            return TRUE;
    }
    return FALSE;
}

static BOOL InstructionIsRipRelativeStore32(hde64s* hs, PBYTE code)
{
    BYTE mod, rm;

    if (hs->opcode != 0x89)
        return FALSE;
    if (!(hs->flags & F_MODRM))
        return FALSE;
    if (!(hs->flags & F_DISP32))
        return FALSE;
    if ((hs->len > 1) && (code[0] == 0x48))
        return FALSE;

    mod = (hs->modrm >> 6) & 0x3;
    rm = hs->modrm & 0x7;
    if (mod != 0 || rm != 5)
        return FALSE;
    return TRUE;
}

static BOOL InstructionIsRegToRegMov(hde64s* hs, PBYTE code, BYTE modRm, BYTE rexMask, BYTE rexValue)
{
    if (hs->opcode != 0x8B)
        return FALSE;
    if (!(hs->flags & F_MODRM))
        return FALSE;
    if (hs->modrm != modRm)
        return FALSE;

    if (hs->len == 2)
        return ((rexMask == 0) && (rexValue == 0));
    if (hs->len != 3)
        return FALSE;

    return InstuctionHasRexPrefix(hs, code, rexMask, rexValue);
}

static ULONG ValidateCiInitializeCode(PBYTE code, ULONG offset, ULONG maxLength)
{
    ULONG pos = offset;
    hde64s hs;

    if (code == NULL || maxLength < 16)
        return 0;
    if (pos >= maxLength)
        return 0;

    /* 1) mov r9, rbx (4C 8B CB) */
    if ((pos + 3) > maxLength)
        return 0;
    RtlSecureZeroMemory(&hs, sizeof(hs));
    hde64_disasm(&code[pos], &hs);
    if (hs.flags & F_ERROR)
        return 0;
    if (!InstructionIsRegToRegMov(&hs, &code[pos], 0xCB, 0x0C, 0x0C))
        return 0;
    pos += hs.len;
    if (pos >= maxLength)
        return 0;

    /* 2) mov r8, rdi (4C 8B C7) or mov r8d, edi (44 8B C7) */
    if ((pos + 3) > maxLength)
        return 0;
    RtlSecureZeroMemory(&hs, sizeof(hs));
    hde64_disasm(&code[pos], &hs);
    if (hs.flags & F_ERROR)
        return 0;
    if (!(InstructionIsRegToRegMov(&hs, &code[pos], 0xC7, 0x0C, 0x0C) ||
          InstructionIsRegToRegMov(&hs, &code[pos], 0xC7, 0x04, 0x04)))
        return 0;
    pos += hs.len;
    if (pos >= maxLength)
        return 0;

    /* 3) mov rdx, rsi (48 8B D6), optionally preceded by mov [rsp+..], rax */
    if ((pos + 3) > maxLength)
        return 0;
    RtlSecureZeroMemory(&hs, sizeof(hs));
    hde64_disasm(&code[pos], &hs);
    if (hs.flags & F_ERROR)
        return 0;

    if (InstructionIsRegToRegMov(&hs, &code[pos], 0xD6, 0x08, 0x08)) {
        pos += hs.len;
    } else if (InstructionIsRspStoreRax(&hs, &code[pos])) {
        pos += hs.len;
        if (pos >= maxLength)
            return 0;
        if ((pos + 3) > maxLength)
            return 0;
        RtlSecureZeroMemory(&hs, sizeof(hs));
        hde64_disasm(&code[pos], &hs);
        if (hs.flags & F_ERROR)
            return 0;
        if (!InstructionIsRegToRegMov(&hs, &code[pos], 0xD6, 0x08, 0x08))
            return 0;
        pos += hs.len;
    } else {
        return 0;
    }

    if (pos >= maxLength)
        return 0;

    /* 4) mov ecx, ebp (8B CD) */
    if ((pos + 2) > maxLength)
        return 0;
    RtlSecureZeroMemory(&hs, sizeof(hs));
    hde64_disasm(&code[pos], &hs);
    if (hs.flags & F_ERROR)
        return 0;
    if (hs.len != 2)
        return 0;
    if (!(hs.flags & F_MODRM))
        return 0;
    if (hs.opcode != 0x8B)
        return 0;
    if (hs.modrm != 0xCD)
        return 0;
    pos += hs.len;

    return pos;
}

BOOL LocateCiOptions(HMODULE mappedBase, ULONG_PTR loadedBase, ULONG_PTR* outVa)
{
    PBYTE ciInitialize;
    PBYTE code;
    ULONG offset = 0;
    LONG relativeValue = 0;
    BOOL found = FALSE;
    hde64s hs;

    *outVa = 0;
    g_dse_locate_error[0] = 0;

    if (!mappedBase || !loadedBase) {
        set_error("invalid mapped/loaded ci.dll base");
        return FALSE;
    }

    ciInitialize = (PBYTE)GetProcAddress(mappedBase, "CiInitialize");
    if (!ciInitialize) {
        set_error("CiInitialize export not found");
        return FALSE;
    }

    code = ciInitialize;
    RtlSecureZeroMemory(&hs, sizeof(hs));

    /* Find the call to CipInitialize inside CiInitialize. */
    do {
        hde64_disasm(&code[offset], &hs);
        if (hs.flags & F_ERROR)
            break;
        if (hs.len == 0)
            break;

        if (hs.len == 3) {
            ULONG k = ValidateCiInitializeCode(code, offset, 256);
            if (k != 0) {
                hde64_disasm(&code[k], &hs);
                if (hs.flags & F_ERROR)
                    break;
                if (hs.len == 0)
                    break;

                if (hs.opcode == 0xE8 && hs.len == 5) {
                    offset = k;
                    relativeValue = *(LONG*)(code + k + 1);
                    found = TRUE;
                    break;
                }
            }
        }

        offset += hs.len;
    } while (offset < 256);

    if (!found) {
        set_error("CipInitialize call not found in CiInitialize");
        return FALSE;
    }

    /* Follow the call, then find the RIP-relative 32-bit store to g_CiOptions. */
    code = code + offset + hs.len + relativeValue;
    offset = 0;
    relativeValue = 0;
    found = FALSE;

    do {
        hde64_disasm(&code[offset], &hs);
        if (hs.flags & F_ERROR)
            break;
        if (hs.len == 0)
            break;

        if (InstructionIsRipRelativeStore32(&hs, &code[offset])) {
            relativeValue = (LONG)hs.disp.disp32;
            found = TRUE;
            break;
        }

        offset += hs.len;
    } while (offset < 256);

    if (!found) {
        set_error("RIP-relative store to g_CiOptions not found in CipInitialize");
        return FALSE;
    }

    code = code + offset + hs.len + relativeValue;
    *outVa = (ULONG_PTR)(loadedBase + (ULONG_PTR)(code - (PBYTE)mappedBase));
    return TRUE;
}
