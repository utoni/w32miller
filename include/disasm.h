#ifndef DISASM_H_INCLUDED
#define DISASM_H_INCLUDED

#include "distorm/distorm.h"


_DecodeResult disasm(_OffsetType codeOffset, const unsigned char* code, int codeLen, _DecodeType dt, _DInst instructions[], unsigned int maxInstructions, unsigned int* usedInstructionsCount);

#endif /* DISASM_H_INCLUDED */
