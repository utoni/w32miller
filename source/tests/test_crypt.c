#include "tests.h"

#include "utils.h"
#include "crypt.h"


#define MIN_BUFSIZ 8192
#define MAX_BUFSIZ 65536


BOOL test_crypt(void)
{
    uint32_t key[8], iv[8];
    size_t ivkeysize = 0, maxsiz = 0;

    maxsiz = MIN_BUFSIZ + (__rdtsc() % (MAX_BUFSIZ-MIN_BUFSIZ+1));
    ivkeysize = 1 + (__rdtsc() % (sizeof(key)/sizeof(key[0])));

    char* randstr = test_randstring(maxsiz);
    ERRETCP( randstr != NULL );
    size_t randlen = strlen(randstr);
    ERRETCP( maxsiz == randlen );
    ERRETCP( randlen >= MIN_BUFSIZ && MAX_BUFSIZ >= randlen );

    for (size_t i = 0; i < ivkeysize; ++i) {
        while(key[i] == 0) key[i] = xor32_randomkey();
        while(iv[i] == 0) iv[i] = xor32_randomkey();
    }

    size_t encsiz = maxsiz + (ivkeysize*sizeof(key[0]));
    char* encBuf = calloc(encsiz, sizeof(char));
    for (size_t i = 0; i < encsiz; ++i)
        ERRETCPDW_NOLOG( *(encBuf + i) == 0x0, *(encBuf + i) );
    memcpy(encBuf, randstr, randlen);
    size_t newsiz = xor32n_pcbc_crypt_buf((uint32_t*)encBuf, maxsiz, &iv[0], &key[0], ivkeysize);
    ERRETCP( memcmp(encBuf, randstr, maxsiz) != 0 );
    size_t oldsiz = xor32n_pcbc_crypt_buf((uint32_t*)encBuf, newsiz, &iv[0], &key[0], ivkeysize);
    ERRETCP( oldsiz == newsiz );
    ERRETCP( memcmp(encBuf, randstr, maxsiz) == 0 );
    free(encBuf);

    COMPAT(free)(randstr);
    return TRUE;
}
