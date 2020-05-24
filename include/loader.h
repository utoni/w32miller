/*
 * WARNING: Any changes in this file require a *FULL* project rebuild!
 *    e.g.: `git clean -df . ; cmake . ; make -j4`
 */

#ifndef LOADER_H_INCLUDED
#define LOADER_H_INCLUDED

#include <stdint.h>

#define LOADER_STR_IVKEYLEN 3
#define LOADER_IVKEYLEN 8

#define TGL_FLAG(ldr, mask) { ldr->flags |= (~ldr->flags & mask); }
#define GET_FLAG(ldr, mask) (ldr->flags & mask)

#define FLAG_EXIT_ONLY      16 /* 0b00010000 -> DLL exits after init (sandbox mode)*/
#define FLAG_SHELLEXEC_ONLY 32 /* 0b00100000 -> DLL calls ShellExecute and exits (e.g. infected usb autoruns) */
#define FLAG_CRYPTED_FUNCS  64 /* 0b01000000 -> DLL has crypted functions which are encrypted during runtime */


/* should be the same structure as described at the end of `source/loader_x86.asm` */
/* This struct is 4-byte aligned! */
typedef struct loader_x86_data {
    /* modified py source/patch.c only */
    uint32_t sizStack;
    /* modified by batch/patchLoader.py (old app: source/tools/host/old/file_crypt.c) */
    char strVirtualAlloc[13];
    char strIsBadReadPtr[13];
    uint32_t iv[8];
    uint32_t key[8];
    /* modified by batch/patchLoader.py */
    uint16_t flags;                 /* DLL Flags */
    uint32_t ptrToDLL;              /* Loader: VA of DLL section       */
    uint32_t sizOfDLL;              /* Loader: size of DLL section     */
    uint32_t endMarker;             /* ENDMARKER */
} __attribute__((packed, gcc_struct)) loader_x86_data;

#endif
