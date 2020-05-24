#include <unistd.h>
#include <time.h>

#include "tests.h"

#include "utils.h"
#include "crypt.h"
#include "math.h"
#include "xor_strings_gen.h"


BOOL test_math(void)
{
    ERRETCP( __moddi3 (100,   50) == 0 );
    ERRETCP( __moddi3 (10000, 11) != 0 );
    ERRETCP( __umoddi3(10000, 11) != 0 );
    ERRETCP( __divdi3 (100,    2) == 50);
    ERRETCP( __divdi3 (1,    1) == 1 );
    ERRETCP( __divdi3 (100,    3) == 33);
    ERRETCP( __divdi3 (1000,9000) == 0 );
    ERRETCP( __moddi3  (LONG_LONG_MAX, LONG_LONG_MAX)  == 0 );
    ERRETCP( __moddi3  (LONG_LONG_MIN, LONG_LONG_MIN)  == 0 );
    ERRETCP( __umoddi3 (LONG_LONG_MAX, LONG_LONG_MAX)  == 0 );
    ERRETCP( __umoddi3 (ULONG_LONG_MAX,ULONG_LONG_MAX) == 0 );
    ERRETCP( __divdi3  (LONG_LONG_MAX,LONG_LONG_MAX ) == 1 );
    ERRETCP( __divdi3  (LONG_LONG_MIN,LONG_LONG_MIN ) == 1 );
    ERRETCP( __udivdi3 (LONG_LONG_MAX,LONG_LONG_MAX ) == 1 );
    ERRETCP( __udivdi3 (ULONG_LONG_MAX,ULONG_LONG_MAX) == 1 );
    ERRETCP( __pow(2,0) == 1 );
    ERRETCP( __pow(2,1) == 2 );
    ERRETCP( __pow(2,10) == 1024 );
    return TRUE;
}

BOOL test_utils(void)
{
    char buf1[64], buf2[64], buf3[64];

    memset(buf1, '\0', 64);
    memset(buf2, '\0', 64);
    memset(buf3, '\0', 64);

    __xultoa(0,              (char*)buf1, 10);
    __xultoa(ULONG_MAX, (char*)buf2, 10);
    __xultoa(LONG_MAX,  (char*)buf3, 10);
    ERRETCP( strcmp(buf1, "0") == 0 );
    ERRETCP( strcmp(buf2, "4294967295") == 0 );
    ERRETCP( strcmp(buf3, "2147483647") == 0 );
    ERRETCP( strlen(buf1) == strlen("0") );
    ERRETCP( strlen(buf2) == strlen("4294967295") );
    ERRETCP( strlen(buf3) == strlen("2147483647") );

    memset(buf1, '\0', 64);
    memset(buf2, '\0', 64);
    memset(buf3, '\0', 64);

    __xltoa(LONG_MAX, (char*)buf1, 10);
    __xltoa(LONG_MIN, (char*)buf2, 10);
    __xltoa(0,             (char*)buf3, 10);
    ERRETCP(  strcmp(buf1, "2147483647") == 0 );
    ERRETCP( strcmp(buf2, "-2147483648") == 0 );
    ERRETCP( strcmp(buf3, "0") == 0 );
    ERRETCP(  strlen(buf1) == strlen("2147483647") );
    ERRETCP( strlen(buf2) == strlen("-2147483648") );
    ERRETCP( strlen(buf3) == strlen("0") );

    char* buf4 = "AA1122334455667788990";
    SIZE_T siz = 0;
    char* result = __xbintostr((BYTE*)buf4, strlen(buf4), 2, &siz);
    ERRETCP( siz == strlen("4141 3131 3232 3333 3434 3535 3636 3737 3838 3939 30") );
    ERRETCP( strcmp(result, "4141 3131 3232 3333 3434 3535 3636 3737 3838 3939 30") == 0 );
    __xfree(result);

    BYTE* buf5 = COMPAT(calloc)(256, sizeof(char));
    for (int i = 0; i < 256; ++i)
        buf5[i] = i;
    result = __xbintostr(buf5, 256, 0, NULL);
    ERRETCP( strlen(result) == 256*2 );
    ERRETCP( strcmp(result, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" \
                    "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F" \
                    "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F" \
                    "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F" \
                    "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F" \
                    "A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF" \
                    "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF" \
                    "E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF") == 0 );
    __xfree(result);


    char* buf6 = strdup("This is a TOP SECRET message!");
    char* buf7 = strdup(buf6);
    unsigned int key = 0;

    while(key == 0) key = xor32_randomkey();

    xor32_byte_crypt((unsigned char*)buf7, strlen(buf6), key);
    ERRETCP( strcmp(buf6, buf7) != 0 )

    xor32_byte_crypt((unsigned char*)buf7, strlen(buf6), key);
    ERRETCP( strlen(buf6) == strlen(buf7) );
    ERRETCP( strcmp(buf6, buf7) == 0 );
    free(buf7);

    char buf9[COMPAT(strlen)(buf6)+1];
    char buf10[COMPAT(strlen)(buf6)+1];

    COMPAT(memcpy)(&buf9[0], buf6, strlen(buf6));
    buf9[COMPAT(strlen)(buf6)] = '\0';
    xor32_byte_crypt((unsigned char*)&buf9[0], COMPAT(strlen)(buf6), key);

    memcpy(&buf10[0], &buf9[0], COMPAT(strlen)(buf6));
    buf10[COMPAT(strlen)(buf6)] = '\0';
    xor32_byte_crypt((unsigned char*)&buf10[0], COMPAT(strlen)(buf6), key);

    ERRETCP( strlen(buf6) == strlen(buf10) );
    ERRETCP( strcmp(buf6, buf9) != 0 );
    ERRETCP( strcmp(buf6, buf10) == 0 );
    free(buf6);

    buf6 = strdup("We want to search a _substring_ in this _string_ !!");
    ERRETCP( COMPAT(strnstr)(buf6, "_substring_", strlen(buf6)) != NULL );
    ERRETCP( COMPAT(strnstr)(buf6, "_string_ !!", strlen(buf6)) != NULL );
    ERRETCP( COMPAT(strnstr)(buf6, "_noonexistant_", strlen(buf6)) == NULL );
    free(buf6);

    buf6 = test_randstring(65535);
    ERRETCP( COMPAT(strnstr)(buf6, "this string should not be found or you got bad luck", strlen(buf6)) == NULL );
    COMPAT(free)(buf6);

    buf6 = strdup("We test if _SubString_ works with strnistr(...)");
    ERRETCP( COMPAT(strnistr)(buf6, "_substring_", strlen(buf6)) != NULL );
    ERRETCP( COMPAT(strnistr)(buf6, "_sUBsTrinG_", strlen(buf6)) != NULL );
    ERRETCP( COMPAT(strnistr)(buf6, "_NOTsubstring_", strlen(buf6)) == NULL );
    ERRETCP( COMPAT(strnistr)(buf6, "STRNISTR(...)", strlen(buf6)) != NULL );
    ERRETCP( COMPAT(strnistr)(buf6, "STRNISTR(...)!", strlen(buf6)) == NULL );
    free(buf6);

    buf6 = test_randstring(65535);
    buf7 = test_randstring(4096);
    ERRETCP( COMPAT(strnistr)(buf6, buf7, strlen(buf6)) == NULL );
    ERRETCP( COMPAT(strnstr)(buf6, buf7, strlen(buf6)) == NULL );
    COMPAT(free)(buf6);
    COMPAT(free)(buf7);

    char* garbage = __genGarbageFormatStr(512);
    ERRETCP( garbage != NULL );
    ERRETCP( strlen(garbage) > 500 );
    COMPAT(free)(garbage);

    struct LogicalDrives devs[32];
    DWORD devnum = dwEnumDrives(&devs[0], sizeof(devs)/sizeof(devs[0]));
    for (DWORD i = 0; i < devnum; ++i) {
        ERRETCPDW( devs[i].devType > 0, devs[i].devType );
        size_t len = strnlen(devs[i].name, MAX_PATH);
        ERRETCP( len > 0 && len <= MAX_PATH );
        if (devs[i].devType == 2 || devs[i].devType == 3) /* DRIVE_REMOVABLE || DRIVE_FIXED */
        {
            ERRETCP( devs[i].bytesPerSectorsPerCluster > 0 );
            ERRETCP( devs[i].totalClusters > 0 );
        }
    }

/*
    // TODO: __pseudoRandom needs an update (not "Random" at all)
    const unsigned max_rnd = 256;
    const unsigned rnd_siz = 128;
    unsigned char rnd[max_rnd][rnd_siz];
    memset(&rnd[0][0], 0, sizeof(rnd));
    for (unsigned i = 0; i < max_rnd; ++i) {
        __pseudoRandom(rnd[i], rnd_siz);
    }
    for (unsigned i = 0; i < max_rnd; ++i) {
        for (unsigned j = 0; j < max_rnd; ++j) {
            if (i == j)
                continue;
            ERRETCP( memcmp(&rnd[i][0], &rnd[j][0], rnd_siz) != 0 );
        }
    }
*/

    char tok_str[] = "This is a sentence seperated with whitespaces without punctuation";
    const unsigned tok_nmb = 9;
    char* tok_next = tok_str;
    char* tok_cur = NULL;
    unsigned tok_n = 0;
    while ((tok_cur = qtok(tok_next, &tok_next)) != NULL && *tok_cur) {
        tok_n++;
    }
    ERRETCP( tok_n == tok_nmb );

    char* str_numbers[] = { "32", "64", "128", "256", "512", "-1", "2700000", "-2700000", "1024e" };
    for (unsigned i = 0; i < sizeof(str_numbers)/sizeof(str_numbers[0]); ++i) {
        char* saveptr = NULL;
        long nmb = COMPAT(strtol)(str_numbers[i], &saveptr, 10);
        ERRETCPDW( nmb != 0, nmb );
        long rnmb = strtol(str_numbers[i], &saveptr, 10);
        ERRETCPDW( nmb == rnmb, rnmb );
    }
    char* str_not_numbers[] = { "abcdef", "abc1024", "a32b32", "a string" };
    for (unsigned i = 0; i < sizeof(str_not_numbers)/sizeof(str_not_numbers[0]); ++i) {
        char* saveptr = NULL;
        long nmb = COMPAT(strtol)(str_not_numbers[i], &saveptr, 10);
        ERRETCPDW( nmb == 0, nmb );
        long rnmb = strtol(str_not_numbers[i], &saveptr, 10);
        ERRETCPDW( nmb == rnmb, rnmb );
    }
    const unsigned max_hex = 64;
    for (unsigned i = 0; i < max_hex; ++i) {
        char* tmp_hex = test_randhexstring(6);
        long nmb = COMPAT(strtol)(tmp_hex, NULL, 16);
        long rnmb = strtol(tmp_hex, NULL, 16);
        ERRETCPDW( nmb == rnmb, rnmb );
        COMPAT(free)(tmp_hex);
    }

#if defined(i386) || defined(i686)
    atomic_val aval = 0;
    ERRETCPDW( aval == 0, aval );
    atomic_inc(&aval);
    ERRETCPDW( aval == 1, aval );
    atomic_val retval = atomic_xchg(&aval, 2);
    ERRETCPDW( aval == 2, aval );
    ERRETCPDW( retval == 1, retval );
#endif
    return TRUE;
}
