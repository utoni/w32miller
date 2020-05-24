#include "compat.h"
#include "utils.h"
#include "crypt.h"
#include "math.h"

#include <limits.h>

#ifndef _NO_UTILS
#include "crypt_strings.h"
#include "xor_strings_gen.h"


DWORD dwEnumDrives(struct LogicalDrives* destPtr, int destLen)
{
    TCHAR szTmp[512];
    TCHAR* p = &szTmp[0];
    DWORD max = destLen;

    if (_GetLogicalDriveStrings(511, szTmp)) {
        do {
            if (destLen-- <= 0)
                return 0;
            COMPAT(memcpy)(&destPtr->name[0], p, MAX_PATH);
            destPtr->devType = _GetDriveType(p);
            DWORD bytesPerSector = 0;
            DWORD sectorsPerCluster = 0;
            if (_GetDiskFreeSpace(p, &sectorsPerCluster, &bytesPerSector,
                                 &destPtr->freeClusters, &destPtr->totalClusters) == TRUE) {
                destPtr->bytesPerSectorsPerCluster = bytesPerSector * sectorsPerCluster;
            }
            while (*p++) {}
        } while (*p && ++destPtr);
    } else return 0;

    return max - destLen;
}

DWORD XMemAlign(DWORD size, DWORD align, DWORD addr)
{
    if (!(size % align))
        return addr + size;
    return addr + (size / align + 1) * align;
}

char* __xstrrev(char* s)
{
    int j,k,c;
    for(k=0; s[k] != 0; k++);
    for(j=0,k--; j<k; j++,k--)
    {
        c = s[j];
        s[j] = s[k];
        s[k] = c;
    }
    return s;
}

char* __xbintostr(const BYTE* buf, SIZE_T siz, SIZE_T delim, SIZE_T* newSizPtr)
{
    register SIZE_T i;
    SIZE_T allocLen = ( delim > 0 ? (int)(siz/delim) : 1 ) + siz*2;
    char* result = COMPAT(calloc)(allocLen+1, sizeof(char));
    char tmp[4];

    DBUF(HEX_ALPHA_ENUM, hexal);
    tmp[3] = '\0';
    for (i = 0; i < siz; ++i)
    {
        unsigned char halfByte = buf[i] >> 4;
        tmp[0] = hexal[halfByte%16];
        halfByte = buf[i] & 0x0F;
        tmp[1] = hexal[halfByte%16];
        tmp[2] = '\0';
        if (delim>0 && i%delim==delim-1)
            tmp[2] = ' ';
        COMPAT(strcat)(result, tmp);
    }
    result[allocLen] = '\0';

    if (newSizPtr)
        *newSizPtr = allocLen;
    return result;
}

char* __xultoa(UINT64 ullval, char *s, int radix)
{
    register int i;

    i=0;
    DBUF(LOWER_ALPHA_ENUM, lower);
    do
    {
        s[i++] = lower[ullval % radix];
        ullval /= radix;
    }
    while(ullval>0);

    s[i] = '\0';
    return __xstrrev(s);
}

char* __xltoa(INT64 n, char *s, int radix)
{
    unsigned long int ullval = 0;
    int i, sign;

    if((sign = (n < 0)) && radix == 10)
        ullval = -n;
    else
        ullval = n;

    DBUF(LOWER_ALPHA_ENUM, lower);
    i=0;
    do
    {
        s[i++] = lower[ullval % radix];
        ullval /= radix;
    }
    while(ullval>0);

    if (sign)
        s[i++] = '-';
    s[i] = '\0';

    return __xstrrev(s);
}

char* __genGarbageFormatStr(size_t garbageSiz)
{
    DBUF(FORMAT_FAKE_ARR_ENUM, fakefmt);
    size_t siz = (sizeof(fakefmt)/sizeof(fakefmt[0]))-1;
    size_t start = 0, end = 0;
    size_t alphaSiz = 0;
    char** alphaArr = COMPAT(calloc)(sizeof(char**), alphaSiz+1);

    for (size_t i = 0; i < siz; ++i)
    {
        if (fakefmt[i] != '\n') {
            end++;
        } else {
            alphaSiz++;
            size_t rndsiz = (__rdtsc() % 5)+1;
            size_t rndnum = __rdtsc() % __pow(10, rndsiz);
            alphaArr = COMPAT(realloc)(alphaArr, alphaSiz*sizeof(char**));
            size_t idx = alphaSiz - 1;
            alphaArr[idx] = COMPAT(calloc)(sizeof(char), end-start+rndsiz+1);
            if ( *(fakefmt + start) == '%' && (__rdtsc() % 2) == 0) {
                char buf[rndsiz+1];
                __xultoa(rndnum, &buf[0], 10);
                buf[rndsiz] = '\0';
                char tmp[2];
                tmp[0] = (unsigned char)'%';
                tmp[1] = '\0';
                size_t alphstart = 0;
                COMPAT(strcat)((alphaArr[idx] + alphstart), tmp);
                alphstart++;
                COMPAT(strcat)((alphaArr[idx] + alphstart), buf);
                alphstart += rndsiz;
                COMPAT(memcpy)(alphaArr[idx] + alphstart, (const void*)(fakefmt + start + 1), end-start-1);
            } else {
                COMPAT(memcpy)(alphaArr[idx], (const void*)(fakefmt + start), end-start);
            }
            end++;
            start = end;
        }
    }

    char* ret = COMPAT(calloc)(sizeof(char), garbageSiz+1);
    size_t cursiz = 0;
    char* buf = NULL;
    do {
        if (buf) {
            COMPAT(strcat)(ret, buf);
            buf = NULL;
        }

        size_t idx = (__rdtsc() % alphaSiz);
        buf = alphaArr[idx];
        cursiz += COMPAT(strlen)(buf);
    }
    while (cursiz < garbageSiz);

    for (size_t i = 0; i < alphaSiz; ++i)
    {
       COMPAT(free)(alphaArr[i]);
    }
    COMPAT(free)(alphaArr);
    return ret;
}

char* __randstring(size_t length, const char* charset)
{
    char *randomString = NULL;
    if (length)
    {
        randomString = COMPAT(calloc)(length+1, sizeof(char));
        if (randomString)
        {
            for (size_t n = 0; n < length; n++)
            {
                int key = __rdtsc() % COMPAT(strlen)(charset);
                randomString[n] = charset[key];
            }
            randomString[length] = '\0';
        }
    }
    return randomString;
}

char* __genRandAlphaNumStr(size_t length)
{
    char* ret = NULL;
    DBUF(LOWER_ALPHA_ENUM, lower);
    ret = __randstring(length, (char*)lower);
    return ret;
}

#if defined(_PRE_RELEASE) || defined(_RUN_TESTS)
void __printByteBuf(const unsigned char* buf, size_t siz)
{
    char* hexbuf = __xbintostr(buf, siz, 0x1, NULL);
    COMPAT(printf)("%s\n", hexbuf);
    COMPAT(free)(hexbuf);
}
#endif

#else
#include <time.h>
#endif /* _NO_UTILS */

uint64_t __rdtsc(void)
{
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

void __pseudoRandom(unsigned char* buf, size_t siz)
{
#ifdef __MINGW32__
    SYSTEMTIME st;
    size_t seed;

    _GetSystemTime(&st);
    seed = ((st.wYear   + st.wMonth   + st.wDayOfWeek +
            st.wDay    + st.wMinute) * (st.wSecond + 1)) + __rdtsc();
    for (size_t i = 0; i < siz; ++i) {
        _GetSystemTime(&st);
        buf[i] = (unsigned char)((seed * st.wMilliseconds) % 256);
        seed++;
    }
#else
    time_t st = time(NULL);
    size_t seed = st + __rdtsc();

    for (size_t i = 0; i < siz; ++i) {
        st = time(NULL);
        buf[i] = (unsigned char)((seed * st) % 256),
        seed++;
    }
#endif
}

/* Strips backslashes from quotes */
static char* unescapeToken(char *token)
{
    char *in = token;
    char *out = token;

    while (*in)
    {
        if (in >= out) {
            break;
        }

        if ((in[0] == '\\') && (in[1] == '"')) {
            *out = in[1];
            out++;
            in += 2;
        } else {
            *out = *in;
            out++;
            in++; 
        }
    }
    *out = 0;
    return token;
}

/* Returns the end of the token, without chaning it. */
char *qtok(char *str, char **next)
{
    char *current = str;
    char *start = str;
    int isQuoted = 0;

    /* Eat beginning whitespace. */
    while (*current && isspace(*current)) current++;
    start = current;

    if (*current == '"') {
        isQuoted = 1;
        /* Quoted token */
        current++; // Skip the beginning quote.
        start = current;
        for (;;) {
            /* Go till we find a quote or the end of string. */
            while (*current && (*current != '"')) current++;
            if (!*current) {
                /* Reached the end of the string. */
                goto finalize;
            }
            if (*(current - 1) == '\\') {
                /* Escaped quote keep going. */
                current++;
                continue;
            }
            /* Reached the ending quote. */
            goto finalize;
        }
    }
    /* Not quoted so run till we see a space. */
    while (*current && !isspace(*current)) current++;
finalize:
    if (*current) {
        /* Close token if not closed already. */
        *current = 0;
        current++;
        /* Eat trailing whitespace. */
        while (*current && isspace(*current)) current++;
    }
    *next = current;

    return isQuoted ? unescapeToken(start) : start;
}

long COMPAT(strtol)(const char* nptr, char** ptr, int base)
{
    register const char *s = nptr;
    register unsigned long acc;
    register int c;
    register unsigned long cutoff;
    register int neg = 0, any, cutlim;

    /*
     * Skip white space and pick up leading +/- sign if any.
     * If base is 0, allow 0x for hex and 0 for octal, else
     * assume decimal; if base is already 16, allow 0x.
     */
    do {
        c = *s++;
    } while (isspace(c));

    if (c == '-') {
        neg = 1;
        c = *s++;
    } else if (c == '+')
        c = *s++;

    if ((base == 0 || base == 16) &&
        c == '0' && (*s == 'x' || *s == 'X')) {
            c = s[1];
            s += 2;
            base = 16;
        }

    if (base == 0)
        base = c == '0' ? 8 : 10;

    /*
     * Compute the cutoff value between legal numbers and illegal
     * numbers.  That is the largest legal value, divided by the
     * base.  An input number that is greater than this value, if
     * followed by a legal input character, is too big.  One that
     * is equal to this value may be valid or not; the limit
     * between valid and invalid numbers is then based on the last
     * digit.  For instance, if the range for longs is
     * [-2147483648..2147483647] and the input base is 10,
     * cutoff will be set to 214748364 and cutlim to either
     * 7 (neg==0) or 8 (neg==1), meaning that if we have accumulated
     * a value > 214748364, or equal but the next digit is > 7 (or 8),
     * the number is too big, and we will return a range error.
     *
     * Set any if any `digits' consumed; make it negative to indicate
     * overflow.
     */

    cutoff = neg ? -(unsigned long)LONG_MIN : LONG_MAX;
    cutlim = cutoff % (unsigned long)base;
    cutoff /= (unsigned long)base;

    for (acc = 0, any = 0;; c = *s++) {
        if (isdigit(c))
            c -= '0';
        else if (isalpha(c))
            c -= isupper(c) ? 'A' - 10 : 'a' - 10;
        else
            break;
        if (c >= base)
            break;

        if (any < 0 || acc > cutoff || (acc == cutoff && c > cutlim))
            any = -1;
        else {
            any = 1;
            acc *= base;
            acc += c;
        }
    }

    if (any < 0) {
        acc = neg ? LONG_MIN : LONG_MAX;
    } else if (neg)
        acc = -acc;

    if (ptr != 0)
        *ptr = (char *) (any ? s - 1 : nptr);

    return (acc);
}

#if defined(i386) || defined(i686)
inline void atomic_inc(atomic_val* ptr)
{
    __asm__ volatile("lock;\n" "incl %0;\n" : "+m"(*ptr));
}

inline atomic_val atomic_xchg(atomic_val* ptr, atomic_val val)
{
    atomic_val tmp = val;
    __asm__ volatile("xchgl %0, %1;\n" : "=r"(tmp), "+m"(*ptr) : "0"(tmp) : "memory");
    return tmp;
}
#endif
