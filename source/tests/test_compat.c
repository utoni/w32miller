#include "tests.h"

#include "compat.h"


BOOL test_heap(void)
{
    ERRETCP(bInitCompat(LoadLibraryA(TEXT("KERNEL32.dll")), GetProcAddress) == TRUE);
    UINT64* hAlloc = __xcalloc(128, sizeof(UINT64));
    ERRETCP(hAlloc != NULL);
    memset(hAlloc, 'A', sizeof(UINT64)*128);
    *(char*)((BYTE*)(hAlloc) + (sizeof(UINT64)*128)-1) = '\0';
    ERRETCP( strlen((char*)hAlloc) == (sizeof(UINT64)*128)-1 );
    __xfree(hAlloc);

    BYTE* bAlloc = __xcalloc(BUFSIZ, sizeof(UINT64));
    ERRETCP(bAlloc != NULL);
    memset(bAlloc, 'A', sizeof(UINT64)*BUFSIZ);
    *(char*)((BYTE*)(bAlloc) + (sizeof(UINT64)*BUFSIZ)-1) = '\0';
    ERRETCP( strlen((char*)bAlloc) == (sizeof(UINT64)*BUFSIZ)-1 );
    __xfree(bAlloc);

    return TRUE;
}

BOOL test_mem(void)
{
    const size_t siz = 128;
    char buf[65];

    memset(buf, 'A', 64);
    *(buf+64) = '\0';

    ERRETCP(bInitCompat(LoadLibraryA(TEXT("KERNEL32.dll")), GetProcAddress) == TRUE);
    char* hAllocOrg =    calloc(siz+1, sizeof(char));
    LPSTR hAlloc    = __xcalloc(siz+1, sizeof(LPSTR));
    ERRETCP(hAlloc != NULL && hAllocOrg != NULL);

    /* memset */
    ERRETCP(memset(hAllocOrg, 'A', siz) != NULL);
    ERRETCP(strlen(hAllocOrg) == siz);
    ERRETCP(__xmemset(hAlloc, 'A', siz) != NULL);
    ERRETCP(strlen(hAlloc)    == siz);
    /* memcpy */
    ERRETCP(memcpy(hAllocOrg, (const void*)buf, sizeof(buf)) != NULL);
    ERRETCP(strlen(hAllocOrg) == sizeof(buf)-1);
    ERRETCP(__xmemcpy(hAlloc, (LPCVOID)buf, sizeof(buf)) != NULL);
    ERRETCP(strlen(hAlloc)    == sizeof(buf)-1);
    /* memmove */
    ERRETCP( memset    (hAllocOrg+ 8, 'B', 8) != NULL );
    ERRETCP( memmove   (hAllocOrg+16, hAllocOrg+4, 8) == (hAllocOrg+16) );
    ERRETCP( memset    (hAllocOrg+ 8, 'A', 8) != NULL );
    ERRETCP( strstr    (hAllocOrg, "BBBB") != NULL );
    ERRETCP( __xmemset (hAlloc   + 8, 'B', 8) != NULL );
    ERRETCP( __xmemmove(hAlloc   +16, hAlloc+4, 8) == (hAlloc+16) );
    ERRETCP( __xmemset (hAlloc   + 8, 'A', 8) != NULL );
    ERRETCP( strstr    (hAlloc,    "BBBB") != NULL );

    __xfree(hAlloc);
    free(hAllocOrg);
    return TRUE;
}

BOOL test_stdio(void)
{
    const char buf1[] = "AAAABBBBAAAACCCC*";
    const size_t len1 = strlen(buf1);

    ERRETCP(bInitCompat(LoadLibraryA(TEXT("KERNEL32.dll")), GetProcAddress) == TRUE);
    ERRETCP( strcmp("BBBB", buf1) == __xstrcmp("BBBB", buf1) );
    ERRETCP( strcmp("DDDD", buf1) == __xstrcmp("DDDD", buf1) );
    ERRETCP( strcmp(buf1, "BBBB") == __xstrcmp(buf1, "BBBB") );
    ERRETCP( strcmp(buf1, "DDDD") == __xstrcmp(buf1, "DDDD") );

    ERRETCP( strncmp("BBBB", buf1, len1) == __xstrncmp("BBBB", buf1, len1) );
    ERRETCP( strncmp("DDDD", buf1, len1) >= __xstrncmp("DDDD", buf1, len1) );
    ERRETCP( strncmp(buf1, "BBBB", len1) == __xstrncmp(buf1, "BBBB", len1) );
    ERRETCP( strncmp(buf1, "DDDD", len1) <= __xstrncmp(buf1, "DDDD", len1) );

    ERRETCP( __xstrnicmp("BBBB", buf1, len1) != 0 );
    ERRETCP( __xstrnicmp("bbbb", buf1, len1) != 0 );
    ERRETCP( __xstrnicmp("dddd", buf1, len1) != 0 );
    ERRETCP( __xstrnicmp("DDDD", buf1, len1) != 0 );
    ERRETCP( __xstrnicmp("AAAA", buf1, len1) == 0 );
    ERRETCP( __xstrnicmp("aaaa", buf1, len1) == 0 );

    ERRETCP( strlen(buf1)        == __xstrlen(buf1) );
    ERRETCP( strnlen(buf1, 0xFF) == __xstrnlen(buf1, 0xFF) );
    ERRETCP( strnlen(buf1, 8)    == __xstrnlen(buf1, 8) );

    char *tmp = COMPAT(strdup)(buf1);
    ERRETCP( strlen(buf1)    == strlen(tmp) );
    ERRETCP( __xstrlen(buf1) == __xstrlen(tmp) );

    ERRETCP( strchr(buf1, '*') == __xstrchr(buf1, '*') );
    ERRETCP( strchr(buf1, '$') == __xstrchr(buf1, '$') );
    COMPAT(free)(tmp);

    char *buf2  = COMPAT(calloc)(128, sizeof(char*));
    char buf3[] = "AAAA";
    COMPAT(strcat)(buf2, buf3);
    size_t len = strlen(buf2);
    ERRETCP( len    == strlen(buf3) );
    ERRETCP( len+4  == strlen(__xstrcat(buf2, "BBBB")) );
    ERRETCP( len+4  == strlen(__xstrcat(buf2, "")) );
    ERRETCP( len+4  == strlen(__xstrcat(buf2, "\0\0\0\0")) );
    ERRETCP( len+12 == strlen(__xstrcat(buf2, "CCCCCCCC")) );
    COMPAT(free)(buf2);

    char* buf4 = COMPAT(calloc)(PRINT_BUFSIZ, sizeof(char));
    char* buf5 = COMPAT(calloc)(PRINT_BUFSIZ, sizeof(char));
    int ret = COMPAT(snprintf)(buf4, PRINT_BUFSIZ, "---%d,%u---\n", 22, (UINT32)-1);
    snprintf(buf5, PRINT_BUFSIZ, "---%d,%u---\n", 22, (UINT32)-1);
    ERRETCP( ret > 0 && ret < PRINT_BUFSIZ );
    ERRETCP( strncmp(buf4, buf5, PRINT_BUFSIZ) == 0);
    COMPAT(free)(buf4);
    COMPAT(free)(buf5);

    buf4 = COMPAT(calloc)(PRINT_BUFSIZ, sizeof(char));
    buf5 = COMPAT(calloc)(PRINT_BUFSIZ, sizeof(char));
    ret = COMPAT(snprintf)(buf4, PRINT_BUFSIZ, "---%d,%u,%d,%d,%c,%p,%p---\n", 22, (UINT32)-1, (INT32)-1, INT_MIN, 'Z', (void*)0xAABBCCFF, (void*)NULL);
    snprintf(buf5, PRINT_BUFSIZ, "---%d,%u,%d,%d,%c,%p,%p---\n", 22, (UINT32)-1, (INT32)-1, INT_MIN, 'Z', (void*)0xAABBCCFF, (void*)NULL);
    ERRETCP( ret > 0 && ret < PRINT_BUFSIZ );
    ERRETCP( strncmp(buf4, buf5, PRINT_BUFSIZ) == 0);
    COMPAT(free)(buf4);
    COMPAT(free)(buf5);

    buf4 = COMPAT(calloc)(PRINT_BUFSIZ, sizeof(char));
    buf5 = COMPAT(calloc)(PRINT_BUFSIZ, sizeof(char));
    ret = COMPAT(snprintf)(buf4, PRINT_BUFSIZ, "---%p,%p,%X,%X---\n", 0x12345678, &buf2, 0x1234, 0x66667777);
    snprintf(buf5, PRINT_BUFSIZ, "---%p,%p,%X,%X---\n", (void*)0x12345678, &buf2, 0x1234, 0x66667777);
    ERRETCP( ret > 0 && ret < PRINT_BUFSIZ );
    ERRETCP( strcmp(buf4, buf5) == 0);
    COMPAT(free)(buf4);
    COMPAT(free)(buf5);

    char* randstr = test_randstring(65535);
    buf5 = COMPAT(calloc)(strlen(randstr)+1, sizeof(char));
    COMPAT(snprintf)(buf5, strlen(randstr)+1, "%s", randstr);
    ERRETCP( strlen(randstr) == strlen(buf5) );
    ERRETCP( strcmp(randstr, buf5) == 0 );
    COMPAT(free)(buf5);

    LPCSTR aStr = TEXT("This is a simple ANSI string if _UNICODE is not defined.");
    int wLen = 0;
    LPWSTR wStr = COMPAT(toWideChar)(aStr, strlen(aStr), &wLen);
    ERRETCP( wLen > 0 );
    ERRETCP( wStr != NULL );
    COMPAT(free)(wStr);

    char sysDir[512];
    char sysWow64Dir[512];
    UINT sysDirRetVal = _GetSystemDirectory(sysDir, sizeof(sysDir));
    ERRETCP( sysDirRetVal > 0 && sysDirRetVal <= sizeof(sysDir) );
    sysDirRetVal = _GetSystemWow64Directory(sysWow64Dir, sizeof(sysWow64Dir));
    ERRETCP( sysDirRetVal > 0 && sysDirRetVal <= sizeof(sysDir) );
    ERRETCP( strncmp(sysDir, sysWow64Dir, sizeof(sysDir)) != 0 );

    return TRUE;
}
