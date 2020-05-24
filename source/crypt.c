#include "compat.h"
#include "crypt.h"
#include "utils.h"

#ifndef __MINGW32__
#include <time.h>
#endif


static inline int xor32_crypt(uint32_t u32, uint32_t key)
{
    return u32 ^ key;
}

uint32_t xor32n_pcbc_crypt_buf(uint32_t* buf, uint32_t siz, const uint32_t* iv, const uint32_t* key, uint32_t ivkeysiz)
{
    uint32_t pad = siz % (ivkeysiz*sizeof(uint32_t));
    if (pad) { 
        siz += (ivkeysiz*sizeof(uint32_t)) - pad;
    }
    uint32_t msiz = (uint32_t)(siz/sizeof(uint32_t));
    uint32_t prev[ivkeysiz];

    for (register uint32_t i = 0; i < ivkeysiz; ++i) {
        prev[i] = iv[i];
    }
    for (register uint32_t i = 0; i < msiz; ++i) {
        register uint32_t plain = buf[i];
        register uint32_t arridx = i % ivkeysiz;
        register uint32_t tmp = xor32_crypt(plain, prev[arridx]);
        register uint32_t crypt = xor32_crypt(tmp, key[arridx]);
        prev[arridx] = xor32_crypt(crypt, plain);
        buf[i] = crypt;
    }
    return siz;
}

unsigned char* xor32_byte_crypt(unsigned char* buf, uint32_t siz, unsigned int key)
{
    uint32_t bsiz  = siz - (siz%4);

    uint32_t i;
    for (i = 0; i < bsiz/4; ++i) {
        unsigned int* src = (unsigned int*)buf;
        unsigned int* dst = (unsigned int*)buf;
        *(dst+i) = *(src+i) ^ key;
    }
    for (i = bsiz; i < bsiz+(siz%4); ++i) {
        unsigned char k = (unsigned char)(key & (0xFF << i*8)) >> i*8;
        buf[i] = buf[i] ^ k;
    }

    return buf;
}

uint32_t xor32_randomkey(void)
{
#ifdef __MINGW32__
    SYSTEMTIME st;
    volatile unsigned int seed, retval;

    _GetSystemTime(&st);
    seed = (seed*retval)+(st.wYear   + st.wMonth   + st.wDayOfWeek +
            st.wDay    + st.wMinute) * (st.wSecond + 1);
    for (int i = 0; i < 100; ++i) { 
        _GetSystemTime(&st);
        retval = (volatile unsigned int)(seed * st.wMilliseconds);
        seed++;
    }
    return (volatile unsigned int)((retval * st.wMilliseconds));
#else
    time_t st = time(NULL);
    volatile unsigned int seed = st * __rdtsc(), retval;

    for (uint32_t i = 0; i < 100; ++i) {
        st = time(NULL);
        retval = (volatile unsigned int)((seed * st) % 256),
        seed++; 
    }
    return (volatile unsigned int)(retval * st);
#endif
}

/* from: https://github.com/jwerle/murmurhash.c */
uint32_t murmurhash(const char *key, uint32_t len, uint32_t seed)
{
    uint32_t c1 = 0xa1f3e2d1;
    uint32_t c2 = 0x4df56a13;
    uint32_t r1 = 15;
    uint32_t r2 = 13;
    uint32_t m  = 5;
    uint32_t n  = 0xa24f697f;
    register uint32_t h  = 0;
    register uint32_t k  = 0;
    uint8_t *d  = (uint8_t *) key; // 32 bit extract from `key'
    const uint32_t *chunks = NULL;
    const uint8_t *tail    = NULL; // tail - last 8 bytes
    register int i = 0;
    int l = len / 4; // chunk length

    h = seed;

    chunks = (const uint32_t *) (d + l * 4); // body
    tail = (const uint8_t *) (d + l * 4); // last 8 byte chunk of `key'

    // for each 4 byte chunk of `key'
    for (i = -l; i != 0; ++i) {
        // next 4 byte chunk of `key'
        k = chunks[i];

        // encode next 4 byte chunk of `key'
        k *= c1;
        k = (k << r1) | (k >> (32 - r1));
        k *= c2;

        // append to hash
        h ^= k;
        h = (h << r2) | (h >> (32 - r2));
        h = h * m + n;
    }

    k = 0;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
    // remainder
    switch (len & 3) { // `len % 4'
        case 3: k ^= (tail[2] << 16);
        case 2: k ^= (tail[1] << 8);
        case 1:
            k ^= tail[0];
            k *= c1;
            k = (k << r1) | (k >> (32 - r1));
            k *= c2;
            h ^= k;
    }
#pragma GCC diagnostic pop

    h ^= len;
    h ^= (h >> 16);
    h *= 0x85ebca6b;
    h ^= (h >> 13);
    h *= 0xc2b2ae35;
    h ^= (h >> 16);

    return h;
}
