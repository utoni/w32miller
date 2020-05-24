#ifndef UTILS_H_INCLUDED
#define UTILS_H_INCLUDED

#include "compat.h"

#define SWAP_ENDIANESS32(x) ((x & 0xFF000000)>>24 | \
                             (x & 0x00FF0000)>> 8 | \
                             (x & 0x0000FF00)<< 8 | \
                             (x & 0x000000FF)<<24)

#define SWAP_ENDIANESS16(x) ((x & 0x0000FF00)>>8 | \
                             (x & 0x000000FF)<<8)

#ifndef STRLEN
#define STRLEN(s) ((sizeof(s)-1)/sizeof(s[0]))
#endif

#ifndef SIZEOF
#define SIZEOF(p) (sizeof(p)/sizeof(p[0]))
#endif

#ifndef isspace
#define isspace(c) (c == 0x20)
#endif
#ifndef isupper
#define isupper(c) (c >= 'A' && c <= 'Z')
#endif
#ifndef islower
#define islower(c) (c >= 'a' && c <= 'z')
#endif
#ifndef isalpha
#define isalpha(c) ( (isupper(c)) || (islower(c)) )
#endif
#ifndef isdigit
#define isdigit(c) (c >= '0' && c <= '9')
#endif

#ifndef _NO_UTILS

#define DEFAULT_DEVS 16
struct LogicalDrives {
    UINT devType;
    DWORD bytesPerSectorsPerCluster;
    DWORD totalClusters;
    DWORD freeClusters;
    char name[MAX_PATH+1];
};


DWORD dwEnumDrives(struct LogicalDrives* destPtr, int destLen);

DWORD XMemAlign(DWORD size, DWORD align, DWORD addr);

char* __xstrrev(char* s);

char* __xbintostr(const BYTE* buf, SIZE_T siz, SIZE_T delim, SIZE_T* newSizPtr);

char* __xultoa(UINT64 ullval, char* s, int radix);

char* __xltoa(INT64 n, char* s, int radix);

char* __genGarbageFormatStr(size_t garbageSiz);

char* __randstring(size_t length, const char* charset);

char* __genRandAlphaNumStr(size_t length);

#if defined(_PRE_RELEASE) || defined(_RUN_TESTS)
void __printByteBuf(const unsigned char* buf, size_t siz);
#endif

#endif /* _NO_UTILS */

uint64_t __rdtsc(void);

void __pseudoRandom(unsigned char* buf, size_t siz);

char* qtok(char *str, char **next);

long COMPAT(strtol)(const char* nptr, char** ptr, int base);

typedef long atomic_val;

#if defined(i386) || defined(i686)
void atomic_inc(atomic_val* ptr);

atomic_val atomic_xchg(atomic_val* ptr, atomic_val val);
#endif

#endif /* UTILS_H_INCLUDED */
