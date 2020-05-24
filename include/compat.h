#ifndef COMPAT_H_INCLUDED
#define COMPAT_H_INCLUDED

#ifndef NULL
#define NULL (void*)0x0
#endif

#ifdef _HOST_TOOLS
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "helper.h"
#define COMPAT(func) func
#else /* _HOST_TOOLS */

#ifdef __MINGW32__
#ifdef _ENABLE_IRC
#include <winsock2.h>
#endif
#include <windows.h>
#include <winhttp.h>
typedef HMODULE (WINAPI *LoadLibraryFunc)    (LPCTSTR);
typedef FARPROC (WINAPI *GetProcAddressFunc) (HMODULE, LPCSTR);
#else
#include <time.h>
#endif /* __MINGW32__ */

#include <stdio.h>

#ifdef _NO_COMPAT
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#define COMPAT(func)       func
#define _LoadLibraryA      LoadLibraryA
#define _GetFileSize       GetFileSize
#define _CreateFile        CreateFile
#define _CloseHandle       CloseHandle
#define _ReadFile          ReadFile
#define _WriteFile         WriteFile
#define _IsBadReadPtr      IsBadReadPtr
#define _GetSystemTime     GetSystemTime
#define _GetModuleFileName GetModuleFileName
#define _GetLastError      GetLastError
#ifndef _USE_PIPES
#define _GetStdHandle      GetStdHandle
#endif /* _USE_PIPES */
#define _WriteConsole      WriteConsole
#else /* _NO_COMPAT */
#include <stdint.h>
#include <stdbool.h>

typedef struct ApiCall {
    void* func_ptr;
} ApiCall_t;

BOOL bInitCompat(void* kernel32, void* getProcAdr);

#ifdef _RUN_TESTS
#define COMPAT(func) __x ## func
#else /* _RUN_TESTS */
#define COMPAT(func) func
#endif /* _RUN_TESTS */

#if defined(_PRE_RELEASE) || defined(_RUN_TESTS)
#ifndef _USE_PIPES
HANDLE _GetStdHandle     (void);
#endif /* _USE_PIPES */
#define PRINT_BUFSIZ 8192
BOOL   _WriteConsole     (const void* buffer, DWORD size, LPDWORD written);
int    COMPAT(puts)      (const char* str);
int    COMPAT(vprintf)   (const char *format, va_list ap);
int    COMPAT(printf)    (const char *format, ...);
#endif /* _PRE_RELEASE) || _RUN_TESTS */

void*  COMPAT(calloc)    (size_t nElements, size_t szElement);

void*  COMPAT(realloc)   (void* ptr, size_t szNew);

const
void*  COMPAT(memmem)    (const void* haystack, size_t haystacklen, const void* needle, size_t needlelen);

void*  COMPAT(memcpy)    (void* dst, const void* src, size_t n);

void*  COMPAT(memmove)   (void* dst, const void* src, size_t siz);

void*  COMPAT(memset)    (void* str, int c, size_t siz);

void   COMPAT(free)      (void* ptr);

int    COMPAT(strcmp)    (const char* str1, const char* str2);

int    COMPAT(strncmp)   (const char* str1, const char* str2, size_t maxCount);

int    COMPAT(strnicmp)  (const char* str1, const char* str2, size_t maxCount);

const
char*  COMPAT(strnstr)   (const char* haytsack, const char* needle, size_t maxCount);

const
char*  COMPAT(strnistr)  (const char* haystack, const char* needle, size_t maxCount);

size_t COMPAT(strlen)    (const char* str);

size_t COMPAT(strnlen)   (const char* str, size_t maxCount);

char*  COMPAT(strdup)    (const char* str);

char*  COMPAT(strchr)    (const char* str, int c);

char*  COMPAT(strcat)    (char *dest, const char *src);

int    COMPAT(vsnprintf) (char* buffer, unsigned int buffer_len, const char *fmt, va_list va);

int    COMPAT(snprintf)  (char* buffer, unsigned int buffer_len, const char *fmt, ...);

LPWSTR COMPAT(toWideChar)(LPCSTR mbStr, int mbLen, int* pOutLen);

BOOL    WINAPI _VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);

HMODULE WINAPI _LoadLibrary        (LPCTSTR name);

FARPROC WINAPI _GetProcAddress     (HMODULE, LPCSTR);

DWORD   WINAPI _GetFileSize        (HANDLE  hFile, LPDWORD lpFileSizeHigh);

HANDLE  WINAPI _CreateFile         (LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                                    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
                                    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

BOOL    WINAPI _CloseHandle        (HANDLE hObject);

BOOL    WINAPI _ReadFile           (HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
                                    LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);

BOOL    WINAPI _WriteFile          (HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
                                    LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);

DWORD   WINAPI _SetFilePointer     (HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);

BOOL    WINAPI _IsBadReadPtr       (const void* lp, UINT_PTR ucb);

void    WINAPI _GetSystemTime      (LPSYSTEMTIME lpSystemTime);

DWORD   WINAPI _GetModuleFileName  (HMODULE hModule, LPTSTR lpFilename, DWORD nSize);

DWORD  WINAPI  _GetLastError       (void);

void   WINAPI  _SetLastError       (DWORD dwErrCode);

void   WINAPI  _OutputDebugString  (LPCTSTR lpcOut);

DWORD  WINAPI  _GetLogicalDriveStrings(DWORD nBufferLength, LPTSTR lpBuffer);

UINT   WINAPI  _GetDriveType       (LPCTSTR lpRootPathName);

BOOL   WINAPI  _GetDiskFreeSpace   (LPCTSTR lpRootPathName, LPDWORD lpSectorsPerCluster, LPDWORD lpBytesPerSector,
                                    LPDWORD lpNumberOfFreeClusters, LPDWORD lpTotalNumberOfClusters);

DWORD  WINAPI  _GetTempPath        (DWORD nBufferLength, LPTSTR lpBuffer);

HANDLE WINAPI  _CreateThread       (LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
                                    LPTHREAD_START_ROUTINE lpStartAddress,
                                    LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

DWORD  WINAPI  _ResumeThread       (HANDLE hThread);

BOOL   WINAPI  _GetThreadContext   (HANDLE hThread, LPCONTEXT lpContext);

BOOL   WINAPI  _SetThreadContext   (HANDLE hThread, const CONTEXT *lpContext);

HANDLE WINAPI  _GetCurrentThread   (void);

DWORD  WINAPI  _WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);

BOOL   WINAPI  _SwitchToThread     (void);

DWORD  WINAPI  _GetVersion         (void);

LPTSTR WINAPI  _GetCommandLine     (void);

void   WINAPI  _GetSystemInfo      (LPSYSTEM_INFO lpSystemInfo);

BOOL   WINAPI  _GetVolumeInformation(LPCTSTR lpRootPathName, LPTSTR lpVolumeNameBuffer, DWORD nVolumeNameSize,
                                     LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength,
                                     LPDWORD lpFileSystemFlags, LPTSTR lpFileSystemNameBuffer, DWORD nFileSystemNameSize);

BOOL  WINAPI   _GetCurrentHwProfile(LPHW_PROFILE_INFOA lpHwProfileInfo);

UINT  WINAPI   _GetSystemDirectory (LPTSTR lpBuffer, UINT uSize);

DWORD WINAPI   _GetCurrentDirectory(DWORD nBufferLength, LPTSTR lpBuffer);

DWORD WINAPI   _GetFileAttributes  (LPCTSTR lpFileName);

BOOL  WINAPI   _EnumDeviceDrivers  (LPVOID *lpImageBase, DWORD cb, LPDWORD lpcbNeeded);

DWORD WINAPI   _GetDeviceDriverBaseNameA(LPVOID ImageBase, LPSTR lpBaseName, DWORD nSize);

HINSTANCE      _ShellExecute       (HWND hwnd, LPCTSTR lpOperation, LPCTSTR lpFile, LPCTSTR lpParameters,
                                    LPCTSTR lpDirectory, INT nShowCmd);

#endif /* _NO_COMPAT */

#endif /* _HOST_TOOLS */

#endif /* COMPAT_H_INCLUDED */
