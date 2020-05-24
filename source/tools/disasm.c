// diStorm64 library sample
// http://ragestorm.net/distorm/
// Arkon, Stefan, 2005
// Mikhail, 2006
// JvW, 2007

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>

// For the compilers who don't have sysexits.h, which is not an ISO/ANSI include!
#define EX_OK           0
#define EX_USAGE       64
#define EX_DATAERR     65
#define EX_NOINPUT     66
#define EX_NOUSER      67
#define EX_NOHOST      68
#define EX_UNAVAILABLE 69
#define EX_SOFTWARE    70
#define EX_OSERR       71
#define EX_OSFILE      72
#define EX_CANTCREAT   73
#define EX_IOERR       74
#define EX_TEMPFAIL    75
#define EX_PROTOCOL    76
#define EX_NOPERM      77
#define EX_CONFIG      78

#include "distorm/distorm.h"
#include "distorm/mnemonics.h"
#include "disasm.h"

// The number of the array of instructions the decoder function will use to return the disassembled instructions.
// Play with this value for performance...
#define MAX_INSTRUCTIONS (1000)


int main(int argc, char **argv)
{
    // Holds the result of the decoding.
    _DecodeResult res;
    // next is used for instruction's offset synchronization.
    // decodedInstructionsCount holds the count of filled instructions' array by the decoder.
    unsigned int decodedInstructionsCount = 0, i, next;

    // Default decoding mode is 32 bits, could be set by command line.
    _DecodeType dt = Decode32Bits;

    // Default offset for buffer is 0, could be set in command line.
    _OffsetType offset = 0;
    char* errch = NULL;

    // Handling file.
    FILE* f;
    unsigned long filesize = 0, bytesread = 0;
    unsigned long long bytesproc = 0, maxbytesproc = (unsigned long long)-1;
    struct stat st;

    // Buffer to disassemble.
    unsigned char *buf, *buf2;

    int opt, show_usage_and_die = 0, use_internal_decode = 0;
    char *filename = NULL;
    while ((opt = getopt(argc, argv, "b:f:m:ip:")) != -1) {
        switch (opt) {
            case 'b':
                if (strncmp(optarg, "16", 2) == 0) {
                    dt = Decode16Bits;
                } else if (strncmp(optarg, "32", 2) == 0) {
                    dt = Decode32Bits;
                } else if (strncmp(optarg, "64", 2) == 0) {
                    dt = Decode64Bits;
                } else {
                    show_usage_and_die = 1;
                }
                break;
            case 'f':
                filename = strdup(optarg);
                break;
            case 'm':
#ifdef SUPPORT_64BIT_OFFSET
                offset = strtoull(optarg, &errch, 16);
#else
                offset = strtoul(optarg, &errch, 16);
#endif
                break;
            case 'i':
                use_internal_decode = 1;
                break;
            case 'p':
                maxbytesproc = strtoull(optarg, &errch, 16);
                break;
        }
    }

    // Check params.
    if (show_usage_and_die || !filename) {
        printf("Usage: %s -i -b[16|32|64] -f[filename] -m[memory offset] -p[memory size]\r\n\tRaw disassembler output.\r\n\tMemory offset is origin of binary file in memory (address in hex).\r\n\tDefault decoding mode is -b32.\r\n\texample: %s -b16 demo.com 789a\r\n\tUse internal decoding with -i\r\n", argv[0], argv[0]);
        return EX_USAGE;
    }

    f = fopen(filename, "rb");
    if (f == NULL) { 
        perror("fopen");
        return EX_NOINPUT;
    }

    if (fstat(fileno(f), &st) != 0) {
        perror("fstat");
        fclose(f);
        return EX_NOINPUT;
    }
    filesize = st.st_size;

    // We read the whole file into memory in order to make life easier,
    // otherwise we would have to synchronize the code buffer as well (so instructions won't be split).
    buf2 = buf = malloc(filesize);
    if (buf == NULL) {
        perror("File too large.");
        fclose(f);
        return EX_UNAVAILABLE;
    }
    bytesread = fread(buf, 1, filesize, f);
    if (bytesread != filesize) {
        perror("Can't read file into memory.");
        free(buf);
        fclose(f);
        return EX_IOERR;
    }

    fclose(f);

    buf += offset;
    filesize -= offset;

    printf("bits: %d\nfilename:%s\norigin: ", dt == Decode16Bits ? 16 : dt == Decode32Bits ? 32 : 64, filename);
#ifdef SUPPORT_64BIT_OFFSET
    if (dt != Decode64Bits) printf("%" PRIx64 "\n", offset);
    else printf("%" PRIx64 "\n", offset);
#else
    printf("%08x\n", offset);
#endif
    printf("size: %" PRIx64 "\n", maxbytesproc);

    if (use_internal_decode) {
        _DInst instData[MAX_INSTRUCTIONS];
        while (1) {
            res = disasm(offset, (const unsigned char*)buf, filesize, dt, instData, MAX_INSTRUCTIONS, &decodedInstructionsCount);
            for (i = 0; i < decodedInstructionsCount; i++) {
#ifdef SUPPORT_64BIT_OFFSET
                printf("%" PRIx64 " (%" PRIu32 ") %04" PRIx16, (uint64_t)instData[i].addr, instData[i].size, instData[i].opcode);
#else
                printf("%08x (%02d) %04" PRIx16, instData[i].addr, instData[i].size, instData[i].opcode);
#endif
                _InstructionType optype = instData[i].opcode;
                switch (optype) {
                    case I_DEC:      printf("\tDEC"); break;
                    case I_INC:      printf("\tINC"); break;
                    case I_ADD:      printf("\tADD"); break;
                    case I_SUB:      printf("\tSUB"); break;
                    case I_MOV:      printf("\tMOV"); break;
                    case I_PUSH:     printf("\tPUSH"); break;
                    case I_POP:      printf("\tPOP"); break;
                    case I_NOP:      printf("\tNOP"); break;
                    case I_JMP:      printf("\tJMP"); break;
                    case I_JMP_FAR:  printf("\tJMP FAR"); break;
                    case I_CALL:     printf("\tCALL"); break;
                    case I_CALL_FAR: printf("\tCALL FAR"); break;
                    case I_RET:      printf("\tRET"); break;
                }
                printf("\r\n");
                bytesproc += instData[i].size;
                if (bytesproc >= maxbytesproc) break;
            }

            if (res == DECRES_SUCCESS) break;
            else if (decodedInstructionsCount == 0) break;
            if (bytesproc >= maxbytesproc) break;
            next = (unsigned int)(instData[decodedInstructionsCount-1].addr - offset);
            next += instData[decodedInstructionsCount-1].size;
            buf += next;
            filesize -= next;
            offset += next;
        }
    } else {
        // Decoded instruction information.
        _DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
        // Decode the buffer at given offset (virtual address).
        while (1) {
            // If you get an undefined reference linker error for the following line,
            // change the SUPPORT_64BIT_OFFSET in distorm.h.
            res = distorm_decode(offset, (const unsigned char*)buf, filesize, dt, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);
            if (res == DECRES_INPUTERR) {
                // Null buffer? Decode type not 16/32/64?
                fputs("Input error, halting!\n", stderr);
                free(buf2);
                return EX_SOFTWARE;
            }

            for (i = 0; i < decodedInstructionsCount; i++) {
#ifdef SUPPORT_64BIT_OFFSET
                printf("%" PRIx64 " (%" PRIu64 ") %-24s %s%s%s\r\n", decodedInstructions[i].offset, (long long unsigned int)decodedInstructions[i].size, (char*)decodedInstructions[i].instructionHex.p, (char*)decodedInstructions[i].mnemonic.p, decodedInstructions[i].operands.length != 0 ? " " : "", (char*)decodedInstructions[i].operands.p);
#else
                printf("%08x (%02d) %-24s %s%s%s\r\n", decodedInstructions[i].offset, decodedInstructions[i].size, (char*)decodedInstructions[i].instructionHex.p, (char*)decodedInstructions[i].mnemonic.p, decodedInstructions[i].operands.length != 0 ? " " : "", (char*)decodedInstructions[i].operands.p);
#endif
                bytesproc += decodedInstructions[i].size;
                if (bytesproc >= maxbytesproc) break;
            }

            if (res == DECRES_SUCCESS) break; // All instructions were decoded.
            else if (decodedInstructionsCount == 0) break;
            if (bytesproc >= maxbytesproc) break;

            // Synchronize:
            next = (unsigned int)(decodedInstructions[decodedInstructionsCount-1].offset - offset);
            next += decodedInstructions[decodedInstructionsCount-1].size;
            // Advance ptr and recalc offset.
            buf += next;
            filesize -= next;
            offset += next;
        }
    }

    free(filename);
    // Release buffer
    free(buf2);

    return EX_OK;
}
