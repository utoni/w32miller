#ifndef AES_H_INCLUDED
#define AES_H_INCLUDED

#include <stdbool.h>
#include <stdint.h>

#define KEY_128 (128/8)
#define KEY_192 (192/8)
#define KEY_256 (256/8)


typedef struct {
    unsigned char state[4][4];
    int kcol;
    uint32_t rounds;
    uint32_t keysched[0];
} aes_ctx_t;


void aes_randomkey(unsigned char* keyout, uint32_t keyLen);

void aes_init();

void aes_cleanup();

aes_ctx_t* aes_alloc_ctx(unsigned char* key, uint32_t keyLen);

char* aes_crypt_s(aes_ctx_t* ctx, const char* input, uint32_t siz, uint32_t* newsiz, bool doEncrypt);

void aes_encrypt(aes_ctx_t* ctx, const unsigned char input[16], unsigned char output[16]);

void aes_decrypt(aes_ctx_t* ctx, const unsigned char input[16], unsigned char output[16]);

void aes_free_ctx(aes_ctx_t* ctx);

#endif // AES_H_INCLUDED
