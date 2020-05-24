#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include "utils.h"
#include "crypt.h"
#include "aes.h"

#define MAX_LINE 65535


static aes_ctx_t* ctx = NULL;
static unsigned char aeskey[KEY_256];
static uint32_t xorkey;
static unsigned xor_align = 4;


char* alignedCopyBuffer(char* orig, unsigned* orig_len, unsigned alignment)
{
    unsigned pad = *orig_len % alignment;
    unsigned new_len = *orig_len + alignment - pad;

    char* out = calloc(new_len, sizeof(char));
    memcpy(out, orig, *orig_len);

    if (pad > 0)
        out[*orig_len] = 0;
    for (unsigned i = (*orig_len)+1; i < new_len; ++i) {
        out[i] = (char)__rdtsc();
    }
    *orig_len = new_len;
    return out;
}

enum defType { DT_DEFAULT, DT_SECTION, DT_ENDSECTION };
struct defines {
    struct defines* next;
    enum defType dt;
    char defName[0];
};
static struct defines* defs = NULL;

void addDefineName(const char* line, enum defType type, struct defines** current)
{
    if (!current) return;

    const char* strb = strchr(line, ' ');
    if (!strb) return;

    while (*(++strb) == ' ') {}

    char* stre = strchr(strb, ' ');
    if (!stre) return;

    size_t len = stre - strb;
    (*current)->next = calloc(sizeof(struct defines) + len + 1, 1);
    (*current) = (*current)->next;
    memcpy( &(*current)->defName[0], &strb[0], len );
    (*current)->dt = type;
}

struct entOpts {
    const char* fmt;
    const char* com;
    const char* ent;
    const char* overw;
};

void writeOrAbort(const char* outbuf, int outsiz, FILE* outfile)
{
    size_t written = fwrite(outbuf, 1, outsiz, outfile);
    if (written != outsiz) {
        fprintf(stderr, "Error while writing \"%.*s\" to OUTPUT stream\n", (outsiz > 20 ? 20 : outsiz), outbuf);
        abort();
    }
}

int addStrEntry(FILE* outfile, const char* name, const struct defines* begin, const struct entOpts* opts, bool addSections)
{
    const char* name_section = NULL;
    const struct defines* cur = begin;
    while ( (cur = cur->next) ) {
        char* outbuf = NULL;
        int outsiz = 0;

        /* error checking */
        if (cur->dt == DT_SECTION && name_section && addSections) {
            fprintf(stderr, "Found SECTION \"%s\" without ENDSECTION for \"%s\"\n", &cur->defName[0], name_section);
            return 1;
        }
        if (cur->dt == DT_ENDSECTION && !name_section && addSections) {
            fprintf(stderr, "Found ENDSECTION \"%s\" without ECTION for \"%s\"\n", &cur->defName[0], name_section);
            return 2;
        }

        /* prepare output buffer */
        if ((opts->fmt && cur->dt == DT_SECTION && !name_section) || (!name_section && !addSections)) {
            /* SECTIONS: generate xor string entries as simple macro */

            if (!addSections) {
                name_section = "ROOT";
                const size_t flen = strlen(opts->fmt);
                const size_t elen = strlen(opts->ent);
                char* fmt = calloc(flen+elen+1, sizeof(char));
                strncpy(fmt, opts->fmt, flen);
                strncpy(fmt+flen, opts->ent, elen);
                outsiz = asprintf(&outbuf, fmt, opts->com, name, name_section, &cur->defName[0]);
                free(fmt);
            } else {
                name_section = &cur->defName[0];
                outsiz = asprintf(&outbuf, opts->fmt, opts->com, name, name_section);
            }
        } else
        if (opts->fmt && cur->dt == DT_ENDSECTION && name_section && addSections) {
            name_section = NULL;
            fseek(outfile, -4, SEEK_CUR);
            writeOrAbort(opts->overw, strlen(opts->overw), outfile);
        } else
        if (name_section && cur->dt == DT_DEFAULT) {
            outsiz = asprintf(&outbuf, opts->ent, &cur->defName[0]);
        }
        /* ignore section entries if user wants only root section entries */
        if (!addSections && cur->dt == DT_SECTION) {
            while ( (cur = cur->next) && cur->dt != DT_ENDSECTION ) {}
        }

        /* write output buffer */
        if (outsiz > 0) {
            writeOrAbort(outbuf, outsiz, outfile);
            free(outbuf);
        }
    }
    fseek(outfile, -4, SEEK_CUR);
    writeOrAbort(opts->overw, strlen(opts->overw), outfile);

    return 0;
}

/* string struct defines for each section */
static const char fmt_strsec[] = "%s\n#define %s_%s_STRINGS \\\n";
static const char com_strsec[] = "\n\n/* for use in string struct */";
static const char fmt_strent[] = "    STRENT(%s), \\\n";
/* replace last 4 bytes with newlines */
static const char overw[]      = "\n\n\n\n";

int addStrStructEntries(FILE* outfile, const char* name, const struct defines* begin, bool addSections)
{
    struct entOpts opts = {0};
    opts.fmt    = fmt_strsec;
    opts.com    = com_strsec;
    opts.ent    = fmt_strent;
    opts.overw  = overw;
    return addStrEntry(outfile, name, begin, &opts, addSections);
}

/* string enum defines for each section */
static const char fmt_enmsec[] = "%s\n#define %s_%s_ENUM \\\n";
static const char com_enmsec[] = "\n\n/* for use in string enum */";
static const char fmt_enment[] = "    %s_ENUM, \\\n";

int addStrEnumEntries(FILE* outfile, const char* name, const struct defines* begin, bool addSections)
{
    struct entOpts opts = {0};
    opts.fmt    = fmt_enmsec;
    opts.com    = com_enmsec;
    opts.ent    = fmt_enment;
    opts.overw  = overw;
    return addStrEntry(outfile, name, begin, &opts, addSections);
}

char* gencstr(unsigned char* buf, size_t siz)
{
    int i;
    char* buf_str = (char*)calloc(1, 4*siz + 1);
    char* buf_ptr = buf_str;
    for (i = 0; i < siz; i++)
    {
        buf_ptr += sprintf(buf_ptr, "\\x%02X", buf[i]);
    }
    *(buf_ptr) = '\0';
    return buf_str;
}

void genUnescapedBuf(char* buf, uint32_t* siz)
{
    int i;
    size_t found = 0;
    bool hasBackslash = false;
    for (i = 0; i < *siz; i++)
    {
        unsigned char byte = 0x00;

        if (buf[i] == '\\') {
            if (hasBackslash) {
                memmove(&buf[i], &buf[i+1], (*siz)-i-1);
                (*siz)--;
                buf[(*siz)] = '\0';
            }
            hasBackslash = !hasBackslash;
            continue;
        }

        if (hasBackslash && buf[i] == 'x') {
            i++;
            for (int j = i; j < i+2; j++) {
                char cur = tolower(buf[j]);
                unsigned char shifter = (j == i ? 4 : 0);
                if (cur == '\0') break;
                if (cur >= 48 && cur <= 57) {
                    byte |= (cur - 48) << shifter;
                } else if (cur >= 97 && cur <= 102) {
                    byte |= (cur - 97 + 10) << shifter;
                }
            }
            i += 2;
            buf[i-4] = byte;
            memmove(buf+i-3, buf+i, (*siz)-i);
            i -= 4;
            hasBackslash = false;
            found++;
        } else
        if (hasBackslash)
            hasBackslash = false;
    }
    *siz -= (found*3);
}

int doSelfTest(void)
{
  int ret = 0;

  unsigned char __aeskey[KEY_256+1];
  memset(&__aeskey[0], '\0', sizeof(unsigned char)*(KEY_256+1));
  aes_randomkey(&__aeskey[0], KEY_256);
  aes_ctx_t* __ctx = aes_alloc_ctx(&__aeskey[0], KEY_256);

  char __ptext[16] = "Attack at dawn!";
  char __ctext[16];
  char __decptext[16];
  aes_encrypt(__ctx, (unsigned char*)__ptext, (unsigned char*)__ctext);
  aes_decrypt(__ctx, (unsigned char*)__ctext, (unsigned char*)__decptext);
  if (strcmp(__ptext, __decptext) != 0) {
    ret = 1;
    goto selftest_fin;
  }

  char __inbuf[] = "This is a short short short short short text, but bigger than 16 bytes ...";
  uint32_t __outlen = 0;
  char* __outbuf = aes_crypt_s(__ctx, __inbuf, sizeof(__inbuf), &__outlen, true);
  uint32_t __orglen = 0;
  char* __orgbuf = aes_crypt_s(__ctx, __outbuf, __outlen, &__orglen, false);

  if (strcmp(__inbuf, __orgbuf) != 0)
    ret = 1;

selftest_fin:
  free(__orgbuf);
  free(__outbuf);
  aes_free_ctx(__ctx);
  return ret;
}

int main(int argc, char** argv)
{
    aes_init();
    struct defines* cur = defs = calloc(sizeof(struct defines), 1);
    int ret = -1;
    if ( (ret = doSelfTest()) != 0) {
        printf("%s: SelfTest failed with %d\n", argv[0], ret);
    }

    if (argc != 5) {
        printf("usage: %s [AES|XOR] [STRING.h] [CRYPTED.h] [KEYNAME-DEFINE]\n", argv[0]);
        printf("e.g.: %s aes include/aes_strings.h include/aes_strings_gen.h AESKEY\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    bool doAes;
    if (strcasecmp(argv[1], "aes") == 0) {
        doAes = true;
    } else if (strcasecmp(argv[1], "xor") == 0) {
        doAes = false;
    } else {
        printf("%s error: [AES|XOR] and not %s\n", argv[0], argv[1]);
        exit(EXIT_FAILURE);
    }

    char* cstr_key = NULL;
    if (doAes) {
        memset(&aeskey[0], '\0', sizeof(aeskey));
        aes_randomkey(&aeskey[0], sizeof(aeskey));

        ctx = aes_alloc_ctx(&aeskey[0], sizeof(aeskey));
        cstr_key = gencstr(&aeskey[0], sizeof(aeskey));
    } else {
        xorkey = xor32_randomkey();
        cstr_key = gencstr((unsigned char*)&xorkey, sizeof(xorkey));
    }

    FILE* infile = fopen(argv[2], "r");
    FILE* outfile = fopen(argv[3], "w+");
    if (!infile || !outfile) {
        printf("%s: %s does not exist!\n", argv[0], (!infile ? argv[2] : argv[3]));
        exit(EXIT_FAILURE);
    }

    char* keydef = NULL;
    char* keysizdef = NULL;
    if (doAes) {
        asprintf(&keydef, "#define %s \"", argv[4]);
        fwrite(keydef, 1, strlen(keydef), outfile);
        fwrite(cstr_key, 1, strlen(cstr_key), outfile);
        fwrite("\"\n", 1, 2, outfile);
        asprintf(&keysizdef, "#define %sSIZ %u\n", argv[4], (unsigned int)(sizeof(aeskey)/sizeof(aeskey[0])));
        fwrite(keysizdef, 1, strlen(keysizdef), outfile);
        free(cstr_key);
    } else {
        asprintf(&keydef, "#define %s ", argv[4]);
        char xorkeystr[12];
        snprintf(&xorkeystr[0], 11, "%u", xorkey);
        xorkeystr[11] = '\0';
        fwrite(keydef, 1, strlen(keydef), outfile);
        fwrite(&xorkeystr[0], 1, strlen(xorkeystr), outfile);
        fwrite("\n", 1, 1, outfile);
        asprintf(&keysizdef, "#define %sSIZ %u\n", argv[4], (unsigned int)sizeof(xorkey));
        fwrite(keysizdef, 1, strlen(keysizdef), outfile);
    }
    free(keysizdef);
    keysizdef = NULL;

    char line[MAX_LINE];
    memset(&line[0], '\0', sizeof(line));
    while (fgets(line, sizeof(line), infile)) {
        char* tmp = line;
        char* enc = NULL; char* header = NULL; char* trailer = NULL;
        uint32_t enclen = 0;
        bool gotStr = false;

        if ( strstr(tmp, "#define") == tmp ) {
            tmp += strlen("#define");
            if ( (tmp = strchr(tmp, '"')) ) {
                tmp++;
                header = tmp;
                char* str = strchr(tmp, '"');
                if (str) {
                    trailer = str;
                    enclen = str-tmp;
                    enc = calloc(sizeof(char), enclen+1);
                    memcpy(enc, tmp, enclen);
                    genUnescapedBuf(enc, &enclen);
                    gotStr = true;
                }
            }
        } else if ( strstr(tmp, "/*") ) {
            if ( (tmp = strchr(tmp, ' ')) ) {
                while (*(++tmp) == ' ') {}
                size_t len = strlen(tmp);
                if (strstr(tmp, "SECTION:") == tmp &&
                        tmp[len-1] == '\n' && tmp[len-2] == '/' &&
                        tmp[len-3] == '*' && tmp[len-4] == ' ') {
                    addDefineName(tmp, DT_SECTION, &cur);
                } else if (strstr(tmp, "ENDSECTION") == tmp) {
                    addDefineName(tmp-1, DT_ENDSECTION, &cur);
                }
            }
        }

        if (gotStr) {
            uint32_t newsiz = 0;
            char* out = NULL;
            if (doAes) {
                out = aes_crypt_s(ctx, enc, enclen, &newsiz, true);
            } else {
                out = alignedCopyBuffer(enc, &enclen, xor_align);
                xor32_byte_crypt((unsigned char*)out, enclen, xorkey);
                newsiz = enclen;
            }
            char* outcstr = gencstr((unsigned char*)out, newsiz);

            fwrite(&line[0], 1, header-&line[0], outfile);
            fwrite(outcstr, 1, strlen(outcstr), outfile);
            fwrite(trailer, 1, strlen(trailer), outfile);
            addDefineName(&line[0], DT_DEFAULT, &cur);

            free(outcstr);
            free(out);
            free(enc);
        } else {
            fwrite(&line[0], 1, strlen(line), outfile);
        }

        memset(&line[0], '\0', sizeof(line));
    }

    if (!doAes) {
        if (addStrStructEntries(outfile, argv[4], defs, true) != 0)
            exit(1);
        if (addStrStructEntries(outfile, argv[4], defs, false) != 0)
            exit(1);
        if (addStrEnumEntries(outfile, argv[4], defs, true) != 0)
            exit(1);
        if (addStrEnumEntries(outfile, argv[4], defs, false) != 0)
            exit(1);
    }

    fclose(infile);
    fclose(outfile);

    free(keydef);
    if (doAes) {
        aes_free_ctx(ctx);
    }
    exit(EXIT_SUCCESS);
}
