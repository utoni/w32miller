#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <errno.h>

#include <sys/mman.h>
#include <ctype.h>

#include "crypt.h"
#include "helper.h"
#include "loader.h"


static const char base64table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const unsigned char loader_endmarker[] = { _LOADER_ENDMARKER };


static void base64_block_encode(const char plain[3], char encoded[4])
{
    unsigned char b0 = 0, b1 = 0, b2 = 0, b3 = 0;

    b0 = ((plain[0] & 0xFC) >> 2);
    b1 = ((plain[1] & 0xF0) >> 4) | ((plain[0] & 0x03) << 4);
    b2 = ((plain[1] & 0x0F) << 2) | ((plain[2] & 0xC0) >> 6);
    b3 = ( plain[2] & 0x3F);
    encoded[0] = base64table[b0];
    encoded[1] = base64table[b1];
    encoded[2] = base64table[b2];
    encoded[3] = base64table[b3];
}

static char* base64_encode(const char* plain, size_t siz, size_t* newsizptr)
{
    size_t padded = (siz % 3 == 0 ? 0 : 3 - (siz % 3));
    size_t newsiz = ( (siz + padded)/3 ) * 4;
    char* tmp = calloc(newsiz, sizeof(char));

    size_t i, j = 0;
    for (i = 0; i < siz-(siz%3); i+=3) {
        base64_block_encode(&plain[i], &tmp[j]);
        j += 4;
    }

    if (padded > 0) {
        char pad[3] = { 0x00, 0x00, 0x00 };
        for (i = 0; i < 3-padded; ++i) {
            pad[i] = plain[siz-(siz%3)+i];
        }

        base64_block_encode(&pad[0], &tmp[j]);

        for (i = 0; i < padded; ++i) {
            tmp[j+3-i] = '=';
        }
    }

    if (newsizptr)
        *newsizptr = newsiz;
    return tmp;
}

static inline int xor32_crypt(uint32_t u32, uint32_t key)
{
    return u32 ^ key;
}

static uint32_t xor32_crypt_buf(uint32_t* buf, uint32_t siz, uint32_t key)
{
    uint32_t pad = siz % sizeof(key);
    if (pad) {
        siz += sizeof(key) - pad;
    }
    uint32_t msiz = (uint32_t)(siz/sizeof(key));

    for (register uint32_t i = 0; i < msiz; ++i) {
        buf[i] = xor32_crypt(buf[i], key);
    }
    return siz;
}

static uint32_t xor32_pcbc_encrypt_buf(uint32_t* buf, uint32_t siz, uint32_t iv, uint32_t key)
{
    uint32_t pad = siz % sizeof(key);
    if (pad) {
        siz += sizeof(key) - pad;
    }
    uint32_t msiz = (uint32_t)(siz/sizeof(key));

    register uint32_t prev = iv;
    for (register uint32_t i = 0; i < msiz; ++i) {
        register uint32_t plain = buf[i];
        register uint32_t tmp = xor32_crypt(plain, prev);
        register uint32_t crypt = xor32_crypt(tmp, key);
        prev = xor32_crypt(crypt, plain);
        buf[i] = crypt;
    }
    return siz;
}

static void xor32_pcbc_decrypt_buf(uint32_t* buf, uint32_t siz, uint32_t iv, uint32_t key)
{
    uint32_t msiz = (uint32_t)(siz/sizeof(key));

    register uint32_t prev = iv;
    for (register uint32_t i = 0; i < msiz; ++i) {
        register uint32_t crypt = buf[i];
        register uint32_t tmp = xor32_crypt(crypt, key);
        register uint32_t plain = xor32_crypt(tmp, prev);
        prev = xor32_crypt(crypt, plain);
        buf[i] = plain;
    }
}

static ssize_t search_endmarker(unsigned char* buf, size_t siz, size_t *found_ptr)
{
    size_t endmarker_siz = sizeof(loader_endmarker)/sizeof(loader_endmarker[0]);
    size_t real_siz = (siz - (siz % endmarker_siz));
    size_t marker_idx = 0, found = 0;
    ssize_t offset = -1;

    for (size_t i = 0; i < real_siz; ++i) {
        if (buf[i] == loader_endmarker[marker_idx++]) {
            if (marker_idx == endmarker_siz) {
                offset = i - (endmarker_siz - 1);
                marker_idx = 0;
                found++;
            }
        } else marker_idx = 0;
    }
    if (found_ptr)
        *found_ptr = found;
    if (found != 1) {
        return -1;
    }
    return offset;
}

static unsigned char* parse_hex_str(const char* hex_str, size_t* newsiz)
{
    const char* pos = hex_str;
    size_t len = strlen(hex_str);

    *newsiz = len/2;
    unsigned char* bin = calloc(*newsiz, sizeof(char));
    size_t i = 0;
    bool skip_next = false;

    while ( *pos != '\0' ) {
        if (!skip_next) {
            if (sscanf(pos, "%2hhx", &bin[i]) == 1) {
                pos++;
                if (tolower(*pos) != 'x') {
                    i++;
                }
                skip_next = true;
                continue;
            }       
        } else skip_next = false;
        pos++;
    }
    *newsiz = i;
    return bin;
}

static void bswap32_endianess(unsigned char* bytebuf, size_t siz)
{
    if (siz % 4 != 0) {
        return;
    }
    for (size_t i = 0; i < siz; i+=4) {
        unsigned char highest_byte = bytebuf[i];
        unsigned char higher_byte  = bytebuf[i+1];
        bytebuf[i]   = bytebuf[i+3];
        bytebuf[i+1] = bytebuf[i+2];
        bytebuf[i+2] = higher_byte;
        bytebuf[i+3] = highest_byte;
    }
}


enum emode { E_NONE = 0, E_BASE64, E_XOR32, E_XOR32PCBC, E_XOR32NPCBC };
enum dmode { D_NONE = 0, D_CRYPT_SZVA, D_CRYPT_SZIB, D_CRYPT_SECTION };

struct options {
    bool verbose;
    bool print_buffer;
    enum emode encmode;
    uint32_t ivkeysize;
    char* outfile;
    char* infile;
    unsigned char* inkey;
    size_t keysize;
    unsigned char* iniv;
    size_t ivsize;
    bool ldrmod;
    off_t ldroffset;
    enum dmode crpmode;
    char* ldr_dll;
    off_t dlloffset;
    size_t dllsize;
    bool dryrun;
} app_options;

static const struct option long_options[] = {
    {"verbose",    no_argument,       0, 'v'},
    {"print-buffer", no_argument,     0, 'p'},
    {"outfile",    required_argument, 0, 'o'},
    {"xor32",      no_argument,       0,  1 },
    {"xor32pcbc",  no_argument,       0,  2 },
    {"xor32npcbc", no_argument,       0,  3 },
    {"ivkeysize",  required_argument, 0, 'k'},
    {"base64",     no_argument,       0,  4 },
    {"key",        required_argument, 0, 'e'},
    {"iv",         required_argument, 0, 'i'},
    {"loader-offset", required_argument, 0, 'l'},
    {"loader-va",  no_argument,       0,  5 },
    {"loader-ib",  no_argument,       0,  6 },
    {"dll-file",   required_argument, 0, 'f'},
    {"dll-hdr",    required_argument, 0,  7 },
    {"dll-section", required_argument, 0, 8 },
    {"dry-run",    no_argument,       0, 'd'},
    {NULL, 0, 0, 0}
};
enum {
    OPTDLL_OFFSET = 0, OPTDLL_SIZE,
    OPTDLL_MAX
};
static char* dllsubopts[] = {
    [OPTDLL_OFFSET] = "offset",
    [OPTDLL_SIZE]   = "size",
    NULL
};
static const char const* options_help[] = {
    "more output",
    "print encrypted/decrypted binary buffers (hex format; massive output!)",
    "output file",
    "simple and unsecure 32-bit xor cipher",
    "unsecure xor32-bit block cipher",
    "secure xor(32*n)-bit block cipher",
    "iv and key size for cipher",
    "base64 (en|de)coder",
    "set a key which should be 4*n bytes long",
    "same behavior as key",
    "binary offset to loader endmarker (see: include/loader.h)",
    "encrypt loader string: strVirtualAlloc",
    "encrypt loader string: strIsBadReadPtr",
    "path to dll binary",
    "encrypt dll header",
    "encrypt dll section (requires argument offset and size)",
    "dont write anything to disk"
};
static const char const opt_fmt[] = "vpo:k:e:i:l:f:dh";

void
print_usage(char* arg0)
{
    fprintf(stderr, "usage: %s [OPTIONS] [INPUTFILE]\n\twhere options can be:\n", arg0);
    const size_t alen = (sizeof(long_options)-sizeof(long_options[0])) / sizeof(long_options[0]);
    for (size_t i = 0; i < alen; ++i) {
        int hlen = ((int)strlen(options_help[i]) + 15) - (int)strlen(long_options[i].name);
        char shortopt = (char)long_options[i].val;
        printf("\t\t");
        if (isalpha(shortopt) != 0) {
            printf("-%c,", shortopt);
        } else {
            hlen += 3;
        }
        printf("--%s", long_options[i].name);
        if (long_options[i].has_arg == required_argument) {
            printf(" [arg]");
        } else {
            hlen += 6;
        }
        printf("%*s\n", hlen, options_help[i]);
    }
}

void
check_loader_arg(char* arg0)
{
    if (app_options.crpmode != D_NONE) {
        fprintf(stderr, "%s: loader crypt mode already set, only ONE allowed\n", arg0);
        exit(1);
    }
}

void
parse_arguments(int argc, char** argv)
{
    int c;

    if (argc <= 1) {
        print_usage(argv[0]);
        exit(1);
    }

    memset(&app_options, '\0', sizeof(app_options));
    while (1) {
        int optind = 0;
        char* endptr = NULL;

        c = getopt_long(argc, argv, opt_fmt, long_options, &optind);
        if (c == -1)
            break;

        switch(c) {
            case 'v':
                app_options.verbose = true;
                break;
            case 'p':
                app_options.print_buffer = true;
                break;
            case 'o':
                app_options.outfile = strdup(optarg);
                break;
            case 1:
                app_options.encmode = E_XOR32;
                break;
            case 2:
                app_options.encmode = E_XOR32PCBC;
                break;
            case 3:
                app_options.encmode = E_XOR32NPCBC;
                break;
            case 'k':
                errno = 0;
                app_options.ivkeysize = strtoul(optarg, &endptr, 10);
                if (errno == ERANGE || errno == EINVAL || *endptr != '\0' || app_options.ivkeysize < 1) {
                    fprintf(stderr, "%s: ivkeysize not an unsigned decimal aka size_t\n", argv[0]);
                    exit(1);
                }
                break;
            case 4:
                app_options.encmode = E_BASE64;
                break;
            case 'e':
                app_options.inkey = parse_hex_str(optarg, &app_options.keysize);
                if (app_options.inkey == NULL) {
                    fprintf(stderr, "%s: not a valid byte-aligned hex string: %s\n", argv[0], optarg);
                    exit(1);
                }
                break;
            case 'i':
                app_options.iniv = parse_hex_str(optarg, &app_options.ivsize);
                if (app_options.iniv == NULL) {
                    fprintf(stderr, "%s: not a valid byte-aligned hex string: %s\n", argv[0], optarg);
                    exit(1);
                }
                break;
            case 'l':
                errno = 0;
                app_options.ldroffset = (size_t)strtoul(optarg, &endptr, 10);
                if (errno == ERANGE || errno == EINVAL || *endptr != '\0') {
                    fprintf(stderr, "%s: ldroffset not an unsigned decimal aka size_t\n", argv[0]);
                    exit(1);
                }
                app_options.ldrmod = true;
                break;
            case 5:
                check_loader_arg(argv[0]);
                app_options.crpmode = D_CRYPT_SZVA;
                break;
            case 6:
                check_loader_arg(argv[0]);
                app_options.crpmode = D_CRYPT_SZIB;
                break;
            case 'f':
                app_options.ldr_dll = strdup(optarg);
                break;
            case 7:
                check_loader_arg(argv[0]);
                app_options.crpmode = D_CRYPT_SECTION;
                errno = 0;
                app_options.dlloffset = 0;
                app_options.dllsize = strtoul(optarg, &endptr, 10);
                if (errno == ERANGE || errno == EINVAL || *endptr != '\0' || app_options.dllsize < 1) {
                    fprintf(stderr, "%s: dll header size is not an unsigned decimal aka size_t\n", argv[0]);
                    exit(1);
                }
                break;
            case 8:
                check_loader_arg(argv[0]);
                app_options.crpmode = D_CRYPT_SECTION;
                char* subopts = optarg;
                char* value = NULL;
                int errfnd = 0;
                int opt;
                while (*subopts != '\0' && !errfnd) {
                    errno = 0;
                    switch ( (opt = getsubopt(&subopts, dllsubopts, &value)) ) {
                        case OPTDLL_OFFSET:
                            if (value)
                                app_options.dlloffset = strtoul(value, &endptr, 10);
                            break;
                        case OPTDLL_SIZE:
                            if (value)
                                app_options.dllsize = strtoul(value, &endptr, 10);
                            break;
                        default:
                            fprintf(stderr, "%s: no match found for token: \"%s\"\n", argv[0], value);
                            errfnd = 1;
                            continue;
                    }
                    if (value == NULL) {
                        fprintf(stderr, "%s: missing value for subopt %s\n", argv[0], dllsubopts[opt]);
                        errfnd = 1;
                    }
                    if (errno == ERANGE || errno == EINVAL || *endptr != '\0') {
                        fprintf(stderr, "%s: dll subopt \"%s\" is not a valid unsigned decimal\n", argv[0], dllsubopts[opt]);
                        errfnd = 1;
                    }
                }
                if (app_options.dlloffset < 1 || app_options.dllsize < 1) {
                    fprintf(stderr, "%s: dll-section requires subopts %s and %s\n", argv[0], dllsubopts[OPTDLL_OFFSET], dllsubopts[OPTDLL_SIZE]);
                    errfnd = 1;
                }
                if (errfnd) {
                    exit(1);
                }
                break;
            case 'd':
                app_options.dryrun = true;
                break;

            case 'h':
            default:
                print_usage(argv[0]);
                exit(1);
        }
    }

    while (optind < argc) {
        if (app_options.infile == NULL) {
            app_options.infile = strdup(argv[optind++]);
        } else {
            fprintf(stderr, "%s: non argv elements\n", argv[optind++]);
            exit(1);
        }
    }

    if (app_options.infile == NULL) {
        fprintf(stderr, "%s: no input file\n", argv[0]);
        exit(1);
    }
    if (app_options.outfile) {
        if (strcmp(app_options.infile, app_options.outfile) == 0) {
            fprintf(stderr, "%s: input file and output file should be two different files\n", argv[0]); 
            exit(1);
        }
    }

    switch (app_options.encmode) {
        case E_NONE:
            fprintf(stderr, "%s: no mode set\n", argv[0]);
            exit(1);
        case E_XOR32:
            if (app_options.iniv != NULL) {
                fprintf(stderr, "%s: iv is not allowed in this mode\n", argv[0]);
                exit(1);
            }
        case E_XOR32PCBC:
            if (app_options.ivkeysize != 0) {
                fprintf(stderr, "%s: setting --ivkeysize not allowed in this mode (ivkeysize=1!)\n", argv[0]);
                exit(1);
            }
            app_options.ivkeysize = 1;
            if ((app_options.inkey != NULL && app_options.keysize != 4) ||
                (app_options.iniv != NULL && app_options.ivsize != 4)) {
                fprintf(stderr, "%s: --iv/--key size MUST be 4 bytes e.g. 0xdeadc0de\n", argv[0]);
                exit(1);
            }
            break;
        case E_XOR32NPCBC:
            if (app_options.crpmode != D_NONE)
                break;
            if (!app_options.inkey && !app_options.iniv && app_options.ivkeysize == 0) {
                fprintf(stderr, "%s: missing ivkeysize\n", argv[0]);
                exit(1);
            }
            if ((app_options.inkey != NULL && app_options.keysize % 4 != 0) ||
                (app_options.iniv != NULL && app_options.ivsize % 4 != 0)) {
                fprintf(stderr, "%s: --iv/--key size MUST be 4*n bytes e.g. 0xdeadc0dedeadbeef\n", argv[0]);
                exit(1);
            }
            if (app_options.inkey != NULL && app_options.iniv != NULL &&
                app_options.keysize != app_options.ivsize) {
                fprintf(stderr, "%s: --iv/--key size MUST be equal\n", argv[0]);
                exit(1);
            }
            if (app_options.inkey != NULL) {
                app_options.ivkeysize = app_options.keysize / 4;
            } else if (app_options.iniv != NULL) {
                app_options.ivkeysize = app_options.ivsize / 4;
            }
            break;
        case E_BASE64:
            if (app_options.inkey != NULL ||
                app_options.iniv != NULL ||
                app_options.ivkeysize != 0) {
                fprintf(stderr, "%s: --iv/--key/--ivkeysize not allowed in base64 mode\n", argv[0]);
                exit(1);
            }
            break;
    }
    if (app_options.crpmode != D_NONE) {
        if (app_options.encmode != E_XOR32NPCBC) {
            fprintf(stderr, "%s: loader modifications only work with xor32npcbc\n", argv[0]);
            exit(1);
        }
        if (app_options.ivkeysize != 0) {
            fprintf(stderr, "%s: setting key/iv size not allowed in this mode\n", argv[0]);
            exit(1);
        }
        if (app_options.crpmode == D_CRYPT_SECTION) {
            if (app_options.ldr_dll == NULL) {
                fprintf(stderr, "%s: missing dll file\n", argv[0]);
                exit(1);
            }
            app_options.ivkeysize = LOADER_IVKEYLEN;
        } else {
            app_options.ivkeysize = LOADER_STR_IVKEYLEN;
        }
        if (app_options.crpmode != D_CRYPT_SECTION && app_options.outfile) {
            fprintf(stderr, "%s: loader modification is done directly at the input binary, --outfile superfluous\n", argv[0]);
            exit(1);
        }
    }
    if (app_options.inkey != NULL) {
        if (app_options.ldrmod == true) {
            if (app_options.keysize != 12) {
                fprintf(stderr, "%s: keysize must be 12 byte for loader string encryption\n", argv[0]);
                exit(1);
            }
        }
        bswap32_endianess(app_options.inkey, app_options.keysize);
    }
    if (app_options.iniv != NULL) {
        if (app_options.ldrmod == true) {
            if (app_options.ivsize != 12) {
                fprintf(stderr, "%s: ivsize must be 12 byte for loader string encryption\n", argv[0]);
                exit(1);
            }
        }
        bswap32_endianess(app_options.iniv, app_options.ivsize);
    }
}

int main(int argc, char** argv)
{
    parse_arguments(argc, argv);
    srandom(time(NULL));
    errno = 0;

    int ret = 0;
    size_t siz = 0;
    char* buf = mapfile(app_options.infile, &siz);
    size_t orgsiz = siz;
    char* orgbuf = buf;
    bool print_crypted_str = false;
    char* dllbuf = NULL;

    if (buf) {
        if (app_options.ldrmod == false) {
            size_t found = 0;
            ssize_t offset = search_endmarker((unsigned char*)buf, siz, &found);
            if (found != 1) {
                fprintf(stderr, "%s: loader marker search error (found: %lu, offset: %ld (0x%X))\n", argv[0], found, offset, (unsigned int)offset);
                exit(1);
            }
            if (app_options.verbose) {
                printf("%s: loader marker found at offset %ld (0x%X)\n", argv[0], offset, (unsigned int)offset);
            }
            app_options.ldroffset = offset;
            app_options.ldrmod = true;
        }

        /* get loader struct */
        struct loader_x86_data* ldr = NULL;
        if (app_options.ldrmod == true) {
            if (memcmp((void*)(orgbuf + app_options.ldroffset),
                       (void*)loader_endmarker,
                       sizeof(loader_endmarker)/sizeof(loader_endmarker[0])) == 0) {
                ldr = (struct loader_x86_data*)(orgbuf +
                       app_options.ldroffset +
                       sizeof(uint32_t) - sizeof(struct loader_x86_data));

                if (memcmp((void*)&ldr->endMarker,
                           (void*)loader_endmarker,
                           sizeof(loader_endmarker)/sizeof(loader_endmarker[0])) != 0) {
                    fprintf(stderr, "%s: loader marker found, but not present after typecast, check loader struct in include/loader.h\n", argv[0]);
                    exit(1);
                }

                char* chk = NULL;
                if (app_options.crpmode == D_CRYPT_SZVA) {
                    buf = ldr->strVirtualAlloc;
                    siz = (sizeof(ldr->strVirtualAlloc)/sizeof(ldr->strVirtualAlloc[0])) -
                          (1 * sizeof(ldr->strVirtualAlloc[0]));
                    chk = buf;
                } else if (app_options.crpmode == D_CRYPT_SZIB) {
                    buf = ldr->strIsBadReadPtr;
                    siz = (sizeof(ldr->strIsBadReadPtr)/sizeof(ldr->strIsBadReadPtr[0])) -
                          (1 * sizeof(ldr->strIsBadReadPtr[0]));
                    chk = buf;
                } else if (app_options.crpmode == D_CRYPT_SECTION) {
                    dllbuf = buf = mapfile(app_options.ldr_dll, &siz);
                    buf += app_options.dlloffset;
                    siz = app_options.dllsize;
                    if (!buf) {
                        fprintf(stderr, "%s: could not map dll file into memory\n", argv[0]);
                        perror("mapfile");
                        exit(1);
                    }
                }
                if (chk)
                    for (size_t i = 0; i < siz; ++i)
                        if (isalpha(buf[i]) == 0) {
                            fprintf(stderr, "%s: non ascii character found in loader string, already encrypted?\n", argv[0]);
                            fprintf(stderr, "%s: forcing --dry-run\n", argv[0]);
                            app_options.dryrun = true;
                            print_crypted_str = true;
                            break;
                        }

                uint32_t tmp[app_options.ivkeysize];
                memset(&tmp[0], '\0', app_options.ivkeysize*sizeof(uint32_t));
                if (memcmp(&tmp[0], &ldr->key[0], app_options.ivkeysize*sizeof(uint32_t)) != 0) {
                    if (app_options.inkey) {
                        fprintf(stderr, "%s: loader->key is not NULL, but --key set?\n", argv[0]);
                        exit(1);
                    } else {
                        app_options.inkey = calloc(app_options.ivkeysize, sizeof(uint32_t));
                        memcpy(app_options.inkey, &ldr->key[0], app_options.ivkeysize*sizeof(uint32_t));
                    }
                }
                if (memcmp(&tmp[0], &ldr->iv[0], app_options.ivkeysize*sizeof(uint32_t)) != 0) {
                    if (app_options.iniv) {
                        fprintf(stderr, "%s: loader->iv is not NULL, but --iv set?\n", argv[0]);
                        exit(1);
                    } else {
                        app_options.iniv = calloc(app_options.ivkeysize, sizeof(uint32_t));
                        memcpy(app_options.iniv, &ldr->iv[0], app_options.ivkeysize*sizeof(uint32_t));
                    }
                }
            } else {
                fprintf(stderr, "%s: loader offset set, but no endmarker found\n", argv[0]);
                exit(1);
            }
        }

        if (app_options.print_buffer) {
            printf("Buffer (Size: %lu):\n", siz);
            printbytebuf(buf, siz, 78, app_options.verbose);
        }

        size_t newsiz = 0;
        char* cryptd = NULL;
        uint32_t key[app_options.ivkeysize];
        uint32_t iv[app_options.ivkeysize];
        memset(&key[0], '\0', app_options.ivkeysize*sizeof(uint32_t));
        memset(&iv[0], '\0', app_options.ivkeysize*sizeof(uint32_t));

        /* copy key/iv if there are any */
        if (app_options.inkey != NULL) {
            memcpy(&key[0], app_options.inkey, app_options.ivkeysize*sizeof(uint32_t));
        }
        if (app_options.iniv != NULL) {
            memcpy(&iv[0], app_options.iniv, app_options.ivkeysize*sizeof(uint32_t));
        }

        /* otherwise generate random iv/key if neccessary */
        for (uint32_t i = 0; i < app_options.ivkeysize; ++i) {
            while (iv[i] == 0) { iv[i] = random(); }
            while (key[i] == 0) { key[i] = random(); }
        }

        /* update loader header */
        if (ldr && !app_options.dryrun) {
            memcpy(&ldr->key[0], &key[0], app_options.ivkeysize*sizeof(uint32_t));
            memcpy(&ldr->iv[0], &iv[0], app_options.ivkeysize*sizeof(uint32_t));
        }

        /* encrypt */
        switch (app_options.encmode) {
            case E_BASE64:
                cryptd = base64_encode(buf, siz, &newsiz);
                break;
            case E_XOR32:
            case E_XOR32PCBC:
                cryptd = calloc(siz + 2*sizeof(uint32_t), sizeof(char));
                memcpy(cryptd, buf, siz);
                if (app_options.encmode == E_XOR32) {
                    if (app_options.verbose) {
                        printf("Xor32Key: %08X\n", key[0]);
                    }
                    newsiz = xor32_crypt_buf((uint32_t*)cryptd, siz, key[0]);
                } else {
                    if (app_options.verbose) {
                        printf("Xor32pcbcKey: %08X\tIV: %08X\n", key[0], iv[0]);
                    }
                    newsiz = xor32_pcbc_encrypt_buf((uint32_t*)cryptd, siz, iv[0], key[0]);
                }
                break;
            case E_XOR32NPCBC:
                cryptd = calloc(siz + (app_options.ivkeysize)*sizeof(uint32_t), sizeof(char));
                memcpy(cryptd, buf, siz);
                if (app_options.verbose) {
                    printf("Xor32npcbcKey/IV:\n");
                    for (uint32_t i = 0; i < app_options.ivkeysize; ++i) {
                        printf("%08X / %08X\n", key[i], iv[i]);
                    }
                }
                newsiz = xor32n_pcbc_crypt_buf((uint32_t*)cryptd, siz, &iv[0], &key[0], app_options.ivkeysize);
                break;
            case E_NONE:
            default:
                break;
        }

        if (app_options.print_buffer) {
            printf("Encoded (Size: %lu):\n", newsiz);
            printbytebuf(cryptd, newsiz, 78, app_options.verbose);
        }

        /* decrypt (and check if algorithm works correctly) */
        switch (app_options.encmode) {
            case E_XOR32:
            case E_XOR32PCBC:
            case E_XOR32NPCBC: {
                char* tmp = calloc(newsiz, sizeof(char));
                memcpy(tmp, cryptd, newsiz);
                if (app_options.encmode == E_XOR32) {
                    newsiz = xor32_crypt_buf((uint32_t*)tmp, newsiz, key[0]);
                } else if (app_options.encmode == E_XOR32PCBC) {
                    xor32_pcbc_decrypt_buf((uint32_t*)tmp, newsiz, iv[0], key[0]);
                } else {
                    xor32n_pcbc_crypt_buf((uint32_t*)tmp, newsiz, &iv[0], &key[0], app_options.ivkeysize);
                }
                if (app_options.print_buffer) {
                    printf("Decoded (Size: %lu):\n", siz);
                    printbytebuf(tmp, siz, 78, app_options.verbose);
                }
                if (memcmp(tmp, buf, siz) != 0) {
                    ret = 1;
                    fprintf(stderr, "%s: ERROR: original buffer and decrypted buffer differs!\n", argv[0]);
                }
                free(tmp);
            }
            case E_BASE64:
            case E_NONE:
            default:
                break;
        }

        /* generate output file */
        if (app_options.outfile) {
            ssize_t written = 0;
            errno = 0;
            if ((written = writebuf(app_options.outfile, (unsigned char*)cryptd, newsiz)) != newsiz) {
                fprintf(stderr, "%s could not write to output file (%lu/%lu bytes written)\n", argv[0], written, newsiz);
                perror("write");
            }
        }

        /* update loader strings/dll section */
        if (!app_options.dryrun &&
            (app_options.crpmode == D_CRYPT_SZVA ||
             app_options.crpmode == D_CRYPT_SZIB ||
             app_options.crpmode == D_CRYPT_SECTION)) {
            memcpy(buf, (unsigned char*)cryptd, newsiz);
        }
        if (print_crypted_str) {
            printf("String: %*s\n", (int)newsiz, cryptd);
        }

        /* unmap files and free memory */
        free(cryptd);
        errno = 0;
        if (app_options.crpmode == D_CRYPT_SECTION && munmap(dllbuf, siz) != 0) {
            fprintf(stderr, "%s: err while unmapping loder dll\n", argv[0]);
            perror("munmap");
            ret = 1;
        }
        errno = 0;
        if (munmap(orgbuf, orgsiz) != 0) {
            perror("munmap");
            ret = 1;
        }
    } else {
        ret = 1;
        perror("mapfile");
    }

    if (ret == 0) {
        printf("%s: succeeded\n", argv[0]);
    }
    return ret;
}
