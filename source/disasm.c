#include "compat.h"
#include "disasm.h"
#include "distorm/distorm.h"


_DecodeResult disasm(_OffsetType codeOffset, const unsigned char* code, int codeLen, _DecodeType dt, _DInst instructions[], unsigned int maxInstructions, unsigned int* usedInstructionsCount)
{
    _DecodeResult res;
    _CodeInfo ci;
    unsigned int instsCount = 0;

    ci.codeOffset = codeOffset;
    ci.code = code;
    ci.codeLen = codeLen;
    ci.dt = dt;
    ci.features = DF_NONE;

    if (dt == Decode16Bits) ci.features = DF_MAXIMUM_ADDR16;
    else if (dt == Decode32Bits) ci.features = DF_MAXIMUM_ADDR32;

    res = distorm_decompose(&ci, instructions, maxInstructions, &instsCount);
    *usedInstructionsCount = instsCount;
    return res;
}
