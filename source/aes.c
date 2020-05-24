// AES Implementation by X-N2O
// Started:  15:41:35 - 18 Nov 2009
// Finished: 20:03:59 - 21 Nov 2009
// Logarithm, S-Box, and RCON tables are not hardcoded
// Instead they are generated when the program starts
// All of the code below is based from the AES specification
// You can find it at http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
// You may use this code as you wish, but do not remove this comment
// This is only a proof of concept, and should not be considered as the most efficient implementation

#include "compat.h"
#include "utils.h"
#include "aes.h"
 
#define AES_RPOL      0x011b // reduction polynomial (x^8 + x^4 + x^3 + x + 1)
#define AES_GEN       0x03   // gf(2^8) generator  (x + 1)
#define AES_SBOX_CC   0x63   // S-Box C constant
 
#define aes_mul(a, b) ((a)&&(b)?g_aes_ilogt[(g_aes_logt[(a)]+g_aes_logt[(b)])%0xff]:0)
#define aes_inv(a)    ((a)?g_aes_ilogt[0xff-g_aes_logt[(a)]]:0)

 
static unsigned char* g_aes_logt = NULL;
static unsigned char* g_aes_ilogt = NULL;
static unsigned char* g_aes_sbox = NULL;
static unsigned char* g_aes_isbox = NULL;
 
 
static inline uint32_t aes_subword(uint32_t w);
static inline uint32_t aes_rotword(uint32_t w);
static void aes_keyexpansion(aes_ctx_t *ctx);
static inline unsigned char aes_mul_manual(unsigned char a, unsigned char b); // use aes_mul instead

static void aes_subbytes(aes_ctx_t *ctx);
static void aes_shiftrows(aes_ctx_t *ctx);
static void aes_mixcolumns(aes_ctx_t *ctx);
static void aes_addroundkey(aes_ctx_t *ctx, int round);
 
static void aes_invsubbytes(aes_ctx_t *ctx);
static void aes_invshiftrows(aes_ctx_t *ctx);
static void aes_invmixcolumns(aes_ctx_t *ctx);


char* aes_crypt_s(aes_ctx_t* ctx, const char* input, uint32_t siz, uint32_t* newsiz, bool doEncrypt)
{
    uint32_t bsiz;
    if (doEncrypt) {
        bsiz = siz + (16 - siz%16);
    } else {
        bsiz = siz;
    }
    char* output = COMPAT(calloc)(1, bsiz+1);
    unsigned char inbuf[16];
    unsigned char outbuf[16];

    uint32_t i = 0;
    for (i = 0; i < bsiz; i=i+16) {
        uint32_t maxsiz;
        if (doEncrypt && bsiz-i <= 16) {
            maxsiz = siz%16;
        } else maxsiz = 16;
        COMPAT(memset)(&inbuf[0], '\0', 16);
        COMPAT(memset)(&outbuf[0], '\0', 16);
        COMPAT(memcpy)( (void*)&inbuf[0], (void*)(input+i), maxsiz);
        if (doEncrypt) {
            aes_encrypt(ctx, inbuf, outbuf);
        } else {
            aes_decrypt(ctx, inbuf, outbuf);
        }
        COMPAT(memcpy)( (void*)(output+i), (void*)&outbuf[0], 16);
    }
    if (newsiz)
        *newsiz = bsiz;
    return output;
}

void aes_randomkey(unsigned char* keyout, uint32_t keyLen)
{
    __pseudoRandom(keyout, keyLen);
} 
 
void aes_init()
{
    int i;
    unsigned char gen;

    g_aes_logt  = COMPAT(calloc)(sizeof(unsigned char), 256);
    g_aes_ilogt = COMPAT(calloc)(sizeof(unsigned char), 256);
    g_aes_sbox  = COMPAT(calloc)(sizeof(unsigned char), 256);
    g_aes_isbox = COMPAT(calloc)(sizeof(unsigned char), 256);
 
    // build logarithm table and it's inverse
    gen = 1;
    for(i = 0; i < 0xff; i++) {
        g_aes_logt[gen]  = i;
        g_aes_ilogt[i]   = gen;
        gen = aes_mul_manual(gen, AES_GEN);
    }
 
    // build S-Box and it's inverse
    for(i = 0; i <= 0xff; i++) {
        char bi;
        unsigned char inv = aes_inv(i);
 
        g_aes_sbox[i] = 0;
        for(bi = 0; bi < 8; bi++) {
            // based on transformation 5.1
            // could also be done with a loop based on the matrix
            g_aes_sbox[i] |= ((inv & (1<<bi)?1:0)
                        ^ (inv & (1 << ((bi+4) & 7))?1:0)
                        ^ (inv & (1 << ((bi+5) & 7))?1:0)
                        ^ (inv & (1 << ((bi+6) & 7))?1:0)
                        ^ (inv & (1 << ((bi+7) & 7))?1:0)
                        ^ (AES_SBOX_CC & (1 << bi)?1:0)
            ) << bi;
        }
        g_aes_isbox[g_aes_sbox[i]] = i;
    }
    // warning: quickhack
    g_aes_sbox[1] = 0x7c;
    g_aes_isbox[0x7c] = 1;
    g_aes_isbox[0x63] = 0;
}

void aes_cleanup(void)
{
    COMPAT(free)(g_aes_logt);
    COMPAT(free)(g_aes_ilogt);
    COMPAT(free)(g_aes_sbox);
    COMPAT(free)(g_aes_isbox);
}
 
aes_ctx_t *aes_alloc_ctx(unsigned char *key, uint32_t keyLen)
{
    aes_ctx_t *ctx;
    uint32_t rounds;
    uint32_t ks_size;
 
    switch(keyLen) {
        case 16: // 128-bit key
            rounds = 10;
            break;
 
        case 24: // 192-bit key
            rounds = 12;
            break;
 
        case 32: // 256-bit key
            rounds = 14;
            break;
 
        default:
            return NULL;
    }

    ks_size = 4*(rounds+1)*sizeof(uint32_t);
    ctx = COMPAT(calloc)(1, sizeof(aes_ctx_t)+ks_size);
    if(ctx) {
        ctx->rounds = rounds;
        ctx->kcol = keyLen/4;
        COMPAT(memcpy)(ctx->keysched, key, keyLen);
        ctx->keysched[43] = 0;
        aes_keyexpansion(ctx);
    }

    return ctx;
}
 
inline uint32_t aes_subword(uint32_t w)
{
    return g_aes_sbox[w & 0x000000ff] |
        (g_aes_sbox[(w & 0x0000ff00) >> 8] << 8) |
        (g_aes_sbox[(w & 0x00ff0000) >> 16] << 16) |
        (g_aes_sbox[(w & 0xff000000) >> 24] << 24);
}
 
inline uint32_t aes_rotword(uint32_t w)
{
    // May seem a bit different from the spec
    // It was changed because unsigned long is represented with little-endian convention on x86
    // Should not depend on architecture, but this is only a POC
    return ((w & 0x000000ff) << 24) |
        ((w & 0x0000ff00) >> 8) |
        ((w & 0x00ff0000) >> 8) |
        ((w & 0xff000000) >> 8);
}
 
void aes_keyexpansion(aes_ctx_t *ctx)
{
    unsigned long temp;
    unsigned long rcon;
    register unsigned int i;
 
    rcon = 0x00000001;
    for(i = ctx->kcol; i < (4*(ctx->rounds+1)); i++) {
        temp = ctx->keysched[i-1];
        if(!(i%ctx->kcol)) {
            temp = aes_subword(aes_rotword(temp)) ^ rcon;
            rcon = aes_mul(rcon, 2);
        } else if(ctx->kcol > 6 && i%ctx->kcol == 4)
            temp = aes_subword(temp);
        ctx->keysched[i] = ctx->keysched[i-ctx->kcol] ^ temp;
    }
}
 
inline unsigned char aes_mul_manual(unsigned char a, unsigned char b)
{
    register unsigned short ac;
    register unsigned char ret;
 
    ac = a;
    ret = 0;
    while(b) {
        if(b & 0x01)
            ret ^= ac;
        ac <<= 1;
        b >>= 1;
        if(ac & 0x0100)
            ac ^= AES_RPOL;
    }
 
    return ret;
}
 
void aes_subbytes(aes_ctx_t *ctx)
{
    int i;
 
    for(i = 0; i < 16; i++) {
        int x, y;
 
        x = i & 0x03;
        y = i >> 2;
        ctx->state[x][y] = g_aes_sbox[ctx->state[x][y]];
    }
}
 
void aes_shiftrows(aes_ctx_t *ctx)
{
    unsigned char nstate[4][4];
    int i;
 
    for(i = 0; i < 16; i++) {
        int x, y;
 
        x = i & 0x03;
        y = i >> 2;
        nstate[x][y] = ctx->state[x][(y+x) & 0x03];
    }
 
    COMPAT(memcpy)(ctx->state, nstate, sizeof(ctx->state));
}
 
void aes_mixcolumns(aes_ctx_t *ctx)
{
    unsigned char nstate[4][4];
    int i;
     
    for(i = 0; i < 4; i++) {
        nstate[0][i] = aes_mul(0x02, ctx->state[0][i]) ^
                aes_mul(0x03, ctx->state[1][i]) ^
                ctx->state[2][i] ^
                ctx->state[3][i];
        nstate[1][i] = ctx->state[0][i] ^
                aes_mul(0x02, ctx->state[1][i]) ^
                aes_mul(0x03, ctx->state[2][i]) ^
                ctx->state[3][i];
        nstate[2][i] = ctx->state[0][i] ^
                ctx->state[1][i] ^
                aes_mul(0x02, ctx->state[2][i]) ^
                aes_mul(0x03, ctx->state[3][i]);
        nstate[3][i] = aes_mul(0x03, ctx->state[0][i]) ^
                ctx->state[1][i] ^
                ctx->state[2][i] ^
                aes_mul(0x02, ctx->state[3][i]);
    }
 
    COMPAT(memcpy)(ctx->state, nstate, sizeof(ctx->state));
}
 
void aes_addroundkey(aes_ctx_t *ctx, int round)
{
    int i;
 
    for(i = 0; i < 16; i++) {
        int x, y;
 
        x = i & 0x03;
        y = i >> 2;
        ctx->state[x][y] = ctx->state[x][y] ^
            ((ctx->keysched[round*4+y] & (0xff << (x*8))) >> (x*8));
    }
}
 
void aes_encrypt(aes_ctx_t *ctx, const unsigned char input[16], unsigned char output[16])
{
    unsigned int i;
 
    // copy input to state
    for(i = 0; i < 16; i++)
        ctx->state[i & 0x03][i >> 2] = input[i];
 
    aes_addroundkey(ctx, 0);
 
    for(i = 1; i < ctx->rounds; i++) {
        aes_subbytes(ctx);
        aes_shiftrows(ctx);
        aes_mixcolumns(ctx);
        aes_addroundkey(ctx, i);
    }
 
    aes_subbytes(ctx);
    aes_shiftrows(ctx);
    aes_addroundkey(ctx, ctx->rounds);
 
    // copy state to output
    for(i = 0; i < 16; i++)
        output[i] = ctx->state[i & 0x03][i >> 2];
}
 
void aes_invshiftrows(aes_ctx_t *ctx)
{
    unsigned char nstate[4][4];
    int i;
 
    for(i = 0; i < 16; i++) {
        int x, y;
 
        x = i & 0x03;
        y = i >> 2;
        nstate[x][(y+x) & 0x03] = ctx->state[x][y];
    }
 
    COMPAT(memcpy)(ctx->state, nstate, sizeof(ctx->state));
}
 
void aes_invsubbytes(aes_ctx_t *ctx)
{
    int i;
 
    for(i = 0; i < 16; i++) {
        int x, y;
 
        x = i & 0x03;
        y = i >> 2;
        ctx->state[x][y] = g_aes_isbox[ctx->state[x][y]];
    }
}
 
void aes_invmixcolumns(aes_ctx_t *ctx)
{
    unsigned char nstate[4][4];
    int i;
     
    for(i = 0; i < 4; i++) {
        nstate[0][i] = aes_mul(0x0e, ctx->state[0][i]) ^
                aes_mul(0x0b, ctx->state[1][i]) ^
                aes_mul(0x0d, ctx->state[2][i]) ^
                aes_mul(0x09, ctx->state[3][i]);
        nstate[1][i] = aes_mul(0x09, ctx->state[0][i]) ^
                aes_mul(0x0e, ctx->state[1][i]) ^
                aes_mul(0x0b, ctx->state[2][i]) ^
                aes_mul(0x0d, ctx->state[3][i]);
        nstate[2][i] = aes_mul(0x0d, ctx->state[0][i]) ^
                aes_mul(0x09, ctx->state[1][i]) ^
                aes_mul(0x0e, ctx->state[2][i]) ^
                aes_mul(0x0b, ctx->state[3][i]);
        nstate[3][i] = aes_mul(0x0b, ctx->state[0][i]) ^
                aes_mul(0x0d, ctx->state[1][i]) ^
                aes_mul(0x09, ctx->state[2][i]) ^
                aes_mul(0x0e, ctx->state[3][i]);
    }
 
    COMPAT(memcpy)(ctx->state, nstate, sizeof(ctx->state));
}
 
void aes_decrypt(aes_ctx_t *ctx, const unsigned char input[16], unsigned char output[16])
{
    int i;
 
    // copy input to state
    for(i = 0; i < 16; i++)
        ctx->state[i & 0x03][i >> 2] = input[i];
 
    aes_addroundkey(ctx, ctx->rounds);
    for(i = ctx->rounds-1; i >= 1; i--) {
        aes_invshiftrows(ctx);
        aes_invsubbytes(ctx);
        aes_addroundkey(ctx, i);
        aes_invmixcolumns(ctx);
    }
 
    aes_invshiftrows(ctx);
    aes_invsubbytes(ctx);
    aes_addroundkey(ctx, 0);
 
    // copy state to output
    for(i = 0; i < 16; i++)
        output[i] = ctx->state[i & 0x03][i >> 2];
}
 
void aes_free_ctx(aes_ctx_t *ctx)
{
    COMPAT(free)(ctx);
}
