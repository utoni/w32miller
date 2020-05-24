#include "tests.h"

#include "compat.h"
#include "loader_x86.h"
#include "distorm/distorm.h"


static volatile unsigned char loader_bin[] = LOADER_SHELLCODE;
#define MAX_INSTRUCTIONS (1000)
static volatile _DecodedInst decodedInstructions[MAX_INSTRUCTIONS];


BOOL test_distorm(void)
{
    ERRETCP(bInitCompat(LoadLibraryA(TEXT("KERNEL32.dll")), GetProcAddress) == TRUE);

    _DecodeType dt = Decode32Bits;
    _DecodeResult res;
    _OffsetType offset = 0;
    unsigned char* buf = (unsigned char*)&loader_bin[0];
    size_t size = sizeof(loader_bin)/sizeof(loader_bin[0]);
    unsigned int decodedInstructionsCount = 0, i, next;

    COMPAT(memset)((unsigned char*)&decodedInstructions[0], '\0', sizeof(_DecodedInst)*MAX_INSTRUCTIONS);
    while (1) {
        res = distorm_decode(offset, buf, size, dt, (_DecodedInst*)&decodedInstructions[0], MAX_INSTRUCTIONS, &decodedInstructionsCount);
        if (res == DECRES_INPUTERR)
            break;

        ERRETCP(res == DECRES_SUCCESS);
        ERRETCP(decodedInstructionsCount > 0);
        for (i = 0; i < decodedInstructionsCount; i++) {
            ERRETCPDW_NOLOG( decodedInstructions[i].offset < size, decodedInstructions[i].offset );
            ERRETCPDW_NOLOG( decodedInstructions[i].size > 0, decodedInstructions[i].size );
            ERRETCPDW_NOLOG( decodedInstructions[i].size < 15, decodedInstructions[i].size );
            ERRETCP_NOLOG( strnlen( (const char*)(&decodedInstructions[i])->mnemonic.p, MAX_TEXT_SIZE ) > 0 );
        }

        if (res == DECRES_SUCCESS) break; // All instructions were decoded.
            else if (decodedInstructionsCount == 0) break;

        // Synchronize:
        next = (unsigned int)(decodedInstructions[decodedInstructionsCount-1].offset - offset);
        next += decodedInstructions[decodedInstructionsCount-1].size;
        // Advance ptr and recalc offset.
        buf += next;
        size -= next;
        offset += next;
    }
    return TRUE;
}
