#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <windows.h>


const char dllpath[] = "libw32miller_pre-shared.dll";


int main(int argc, char** argv) {
    char* path = NULL;
    BOOL hasPathToDLL = FALSE;

    if (argc == 2) {
        path = argv[1];
        hasPathToDLL = TRUE;
    } else if (argc == 1) {
        path = dirname(argv[0]);
    } else {
        printf("usage: %s [|PATH_TO_DLL]\n", argv[0]);
        return 1;
    }
 
#ifdef _MILLER_IMAGEBASE
    /* force windows loader to relocate module */
    LPVOID vpointer = VirtualAlloc((LPVOID)_MILLER_IMAGEBASE, 0x1000, MEM_RESERVE, PAGE_READWRITE);
    if (!vpointer) {
        printf("VirtualAlloc..: %ld\n", GetLastError());
    } else {
        printf("Ptr-alloc'd...: 0x%p\n", vpointer);
    }
#else
        printf("WARN..........: Ptr-alloc disabled ( missing macro `-D_MILLER_IMAGEBASE=[HEX-VALUE]` )\n");
#endif


    HANDLE h = NULL;

    if (!hasPathToDLL) {
        SetDllDirectory(path);
        printf("DLL-dir.......: %s\n", path);
        printf("DLL-file......: %s\n", dllpath);
        h = LoadLibrary(dllpath);
    } else {
        printf("DLL-file......: %s\n", path);
        h = LoadLibrary(path);
    }

    if (!h) {
        printf("LoadLibrary...: %ld\n", GetLastError());
    } else {
        printf("LoadLibrary...: %s\n", "SUCCESS");
    }

    printf("Library HANDLE: 0x%p\n", h);
    return 0;
}
