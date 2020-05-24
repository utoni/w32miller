#include "tests.h"

#include "utils.h"
#include "file.h"
#include "pe_infect.h"
#include "patch.h"
#include "xor_strings.h"


BOOL test_pe(char* filename)
{
    HANDLE hFile;
    BYTE* buf;
    SIZE_T szBuf;
    struct ParsedPE ppe;

    memset(&ppe, '\0', sizeof(struct ParsedPE));
    ERRETCP( bOpenFile(filename, 0, &hFile) == TRUE );
    ERRETCP( bFileToBuf(hFile, &buf, &szBuf) == TRUE );
    ERRETCP( bParsePE(buf, szBuf, &ppe, FALSE) == TRUE );
    ERRETCP( ppe.valid == TRUE );
    ERRETCP( bIsInfected(&ppe) == FALSE );
    ERRETCP( pGetSegmentAdr(".text", TRUE, &ppe, NULL) != NULL );
    ERRETCP( pGetSegmentAdr(".data", TRUE, &ppe, NULL) != NULL );
    ERRETCP( pGetSegmentAdr(".rdata", TRUE, &ppe, NULL) != NULL );
    ERRETCP( pGetSegmentAdr(".idata", TRUE, &ppe, NULL) != NULL );
    ERRETCP( pGetSegmentAdr(".CRT", TRUE, &ppe, NULL) != NULL );
    ERRETCP( pGetSegmentAdr(LDRSECTION, TRUE, &ppe, NULL) == NULL );
    ERRETCP( pGetSegmentAdr(DLLSECTION, TRUE, &ppe, NULL) == NULL );
    ERRETCP( PtrToRva(&ppe, pGetSegmentAdr(".text", TRUE, &ppe, NULL)) != (DWORD)-1 );
    ERRETCP( PtrToRva(&ppe, pGetSegmentAdr(".text", TRUE, &ppe, NULL)) > (DWORD)ppe.hdrOptional->ImageBase );
    ERRETCP( OffsetToRva(&ppe, PtrToOffset(&ppe, pGetSegmentAdr(".text", TRUE, &ppe, NULL))) <
                 OffsetToRva(&ppe, PtrToOffset(&ppe, pGetSegmentAdr(".data", TRUE, &ppe, NULL))) );

    free(buf);
    CloseHandle(hFile);

    BYTE jmp[5];
    patchRelJMP(jmp, 0x44332211);
    ERRETCP( strncmp((char*)jmp, "\xE9\x11\x22\x33\x44", 5) == 0 );

    char* test_dir = dirname(filename);
    char* loader_file = NULL;
    asprintf(&loader_file, "%s\\loader_base.exe", test_dir);
    if (bOpenFile(loader_file, 0, &hFile) == TRUE) {
        ERRETCP( bFileToBuf(hFile, &buf, &szBuf) == TRUE );
        ERRETCP( bParsePE(buf, szBuf, &ppe, FALSE) == TRUE );
        ERRETCP( ppe.valid == TRUE );
        ERRETCP( ppe.hasDLL == TRUE );
        ERRETCP( ppe.hasLdr == TRUE );
        ERRETCP( bIsInfected(&ppe) == TRUE );
        ERRETCP( ppe.ptrToDLL != NULL );
        ERRETCP( ppe.ptrToLdr != NULL );
        ERRETCP( bCheckEndMarker(&ppe) == TRUE );
        ERRETCP( ppe.loader86 != NULL );
        ERRETCP( ppe.loader86->ptrToDLL != 0 );
        ERRETCP( ppe.loader86->sizOfDLL != 0 );
        size_t ldrstrsiz = sizeof(ppe.loader86->strVirtualAlloc)/sizeof(ppe.loader86->strVirtualAlloc[0]);
        ERRETCP( ppe.loader86->strVirtualAlloc[ldrstrsiz-1] == '\0' );
        ERRETCP( ppe.loader86->strIsBadReadPtr[ldrstrsiz-1] == '\0' );
        DWORD dwImpLibs = dwCountNonSystemImportLibs(&ppe);
        ERRETCPDW( dwImpLibs == 0, dwImpLibs );
    } else ERRPRINT_STDERR("Could not OpenFile: %s\n", loader_file);
    free(loader_file);
    return TRUE;
}
