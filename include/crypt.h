#ifndef CRYPT_H_INCLUDED
#define CRYPT_H_INCLUDED

#include <stdint.h>


/* a possible encrypted function should use this macro */
#define POSSIBLE_CRYPT_FUNC(func, ...) \
    printf("FUNC-PTR: %p\n", func); \
    func(__VA_ARGS__)

/* AES-256 function prolog */
#define CRYPT_PROLOG \
    asm goto ("jmp %l0\n"  \
        : /* no output */  \
        : /* no input */   \
        : /* no clobber */ \
        : ___after_crypt_header); \
    __asm__ __volatile__(  \
        ".intel_syntax noprefix\n" \
        ".byte 0xac,0xab,0x00,0x00,0x00,0x00\n\t" \
        ".att_syntax\n" \
    ); \
    ___after_crypt_header:

/* 16 byte pad for AES-256 encryption */
#define CRYPT_EPILOG \
    asm volatile( \
        ".intel_syntax noprefix\n" \
        "nop; nop; nop; nop; nop; nop; nop; nop\n\t" \
        "nop; nop; nop; nop; nop; nop; nop; nop\n\t" \
        ".att_syntax\n" \
    )

#define XOR128_KEYSIZ 4
#define XOR256 KEYSIZ 8


uint32_t xor32n_pcbc_crypt_buf(uint32_t* buf, uint32_t siz, const uint32_t* iv, const uint32_t* key, uint32_t ivkeysiz);

unsigned char* xor32_byte_crypt(unsigned char* buf, uint32_t siz, uint32_t key);

uint32_t xor32_randomkey(void);

uint32_t murmurhash(const char *key, uint32_t len, uint32_t seed);

#endif /* CRYPT_H_INCLUDED */
