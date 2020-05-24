#include <stdio.h>
#include <stdlib.h>

#include <windows.h>

#include "http.h"


const char tm_proc[] = "tor_main@8";
const unsigned int default_port = 59050;
const unsigned int ident = 0xdeadc0de;

int main(int argc, char** argv)
{
    unsigned int pport = default_port;

    if (argc < 2) {
        fprintf(stderr, "usage: %s [Path-To-LibTor.dll] [Proxy-Port]\n", argv[0]);
        exit(1);
    }
    if (argc >= 3) {
        pport = atoi(argv[2]);
        if (pport == 0)
            pport = default_port;
    }

    SetLastError(0);
    HMODULE hLibTor = LoadLibraryA(argv[1]);
    tor_main_t tor_main = NULL;
    if (hLibTor) {
        tor_main = (tor_main_t) GetProcAddress(hLibTor, tm_proc);
    }

    printf("libtor..: 0x%p\n"
           "tor_main: 0x%p\n"
           "error...: %lu\n"
           , hLibTor, tor_main, GetLastError());

    if (tor_main)  {
        printf("\nCalling %s(%u, 0x%p) ..\n", tm_proc, pport, (void*)ident);
        int ret = tor_main(pport, ident);
        if (ret == 0) {
            printf("%s succeeded\n", tm_proc);
        } else {
            printf("%s returned: %d\n", tm_proc, ret);
        }
        exit(ret);
    } else {
        fprintf(stderr, "Did not find \"%s\" int %s\n", tm_proc, argv[1]);
        exit(1);
    }
}
