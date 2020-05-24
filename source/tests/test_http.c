#include <unistd.h>
#include <time.h>

#include "tests.h"

#include "http.h"
#include "math.h"
#include "utils.h"


BOOL addPkg(SIZE_T sizA, SIZE_T sizB, struct http_resp* hresp, rrbuff* dst_buf, rrsize* dst_siz)
{
    ERRETCP( dst_buf != NULL && dst_siz != NULL && hresp != NULL );

    rrsize new_siz = *dst_siz + sizA + sizeof(*hresp) + sizB;
    *dst_buf = realloc(*dst_buf, new_siz*sizeof(**dst_buf));

    rrbuff new_buf = *dst_buf + *dst_siz;
    memset(new_buf, 'A', sizA);
    memcpy(new_buf + sizA, hresp, sizeof(*hresp));
    memset(new_buf + sizA + sizeof(*hresp), 'B', sizB);

    *dst_siz = new_siz;
    return TRUE;
}

#define PARSE_RESPONSE_CLEANUP(pkgbuf, pkgsiz, pkg_count, hresp) \
                                        if (pkgbuf != NULL) free(pkgbuf); \
                                        pkgbuf = NULL; \
                                        pkgsiz = 0; \
                                        pkg_count = 0; \
                                        memset(&hresp, 0, sizeof(hresp)); \
                                        memset(&hresp.startMarker[0], 'c', MARKER_SIZ);

BOOL test_http(void)
{
    DWORD init_ret = ERR_HTTP_PRE;
    ERRETCPDW( (init_ret = initHttp(LoadLibraryA, GetProcAddress)) == ERR_HTTP_OK, init_ret );

    uint64_t sizA = __rdtsc() % 256;
    uint64_t sizB = __rdtsc() % 512;
    struct http_resp hresp = { {0}, 0, 0, 0 };
    rrbuff pkgbuf = NULL;
    rrsize pkgsiz = 0;
    DWORD pkg_count = 0;

    PARSE_RESPONSE_CLEANUP(pkgbuf, pkgsiz, pkg_count, hresp);

    {
        hresp.respCode = RC_REGISTER;
        ERRETCP( addPkg(sizA, sizB, &hresp, &pkgbuf, &pkgsiz) == TRUE );
        ERRETCP( addPkg(sizA, sizB, &hresp, &pkgbuf, &pkgsiz) == TRUE );
        hresp.respCode = RC_PING;
        ERRETCP( addPkg(sizA, sizB, &hresp, &pkgbuf, &pkgsiz) == TRUE );
        pkg_count = 3;
    }

    {
        int ret;
        struct http_resp* tmp_hresp = NULL;
        size_t pkgoff = 0;
        while ((ret = parseResponse(pkgbuf, pkgsiz, &tmp_hresp, &pkgoff, &hresp.startMarker[0])) == RSP_OK ) {
            ERRETCP( tmp_hresp != NULL );
            pkg_count--;
        }
        if (pkg_count != 0)
            ERRPRINT_BOTH("Last parseResponse returned: %d", ret);
        ERRETCPLD( pkg_count == 0, pkg_count );
    }

    PARSE_RESPONSE_CLEANUP(pkgbuf, pkgsiz, pkg_count, hresp);

    {
        rflags all_flags[] = RF_ALL;
        rrcode all_codes[] = RC_ALL;
        for (DWORD i = 0; i < SIZEOF(all_codes); ++i) {
            for (DWORD j = 0; j < SIZEOF(all_flags); ++j) {
                hresp.respFlags = all_flags[j];
                hresp.respCode = all_codes[i];
                ERRETCP( addPkg(sizA, sizB, &hresp, &pkgbuf, &pkgsiz) == TRUE );
                pkg_count++;
            }
        }
        int ret;
        struct http_resp* tmp_hresp = NULL;
        size_t pkgoff = 0;
        while ((ret = parseResponse(pkgbuf, pkgsiz, &tmp_hresp, &pkgoff, &hresp.startMarker[0])) == RSP_OK ) {
            ERRETCP( tmp_hresp != NULL );
            pkg_count--;
        }
        if (pkg_count != 0)
            ERRPRINT_BOTH("Last parseResponse returned: %d", ret);
        ERRETCPLD( pkg_count == 0, pkg_count );
    }

    PARSE_RESPONSE_CLEANUP(pkgbuf, pkgsiz, pkg_count, hresp);

    {
        DWORD maxPkgs = 64;
        for (DWORD i = 0; i < maxPkgs; ++i) {
            hresp.respCode = RC_PING;
            ERRETCP( addPkg(sizA, sizB, &hresp, &pkgbuf, &pkgsiz) == TRUE );
            pkg_count++;
        }
        ERRETCPLD( pkg_count == maxPkgs, pkg_count );
    }

    PARSE_RESPONSE_CLEANUP(pkgbuf, pkgsiz, pkg_count, hresp);

    {
        int abs_count = 0;
        rrcode all_codes[] = RC_ALL;
        DWORD maxPkgs = 64;
        DWORD validPkgs = 0;
        for (DWORD i = 0; i < maxPkgs; ++i) {
            rrcode rc;
            int rnd;
            while ((rnd = __rdtsc()) == 0) {}
            if (rnd % 2 == 0)
                rc = all_codes[ __rdtsc() % SIZEOF(all_codes) ];
            else
                rc = (rrcode)__rdtsc();
            for (DWORD j = 0; j < SIZEOF(all_codes); ++j) {
                if (all_codes[j] == rc) {
                    pkg_count++;
                    validPkgs++;
                    break;
                }
            }
            abs_count++;
            hresp.respCode = rc;
            ERRETCP( addPkg(0, 0, &hresp, &pkgbuf, &pkgsiz) == TRUE );
        }
        int ret;
        struct http_resp* tmp_hresp = NULL;
        size_t pkgoff = 0;
        while (abs_count > 0) {
            if ((ret = parseResponse(pkgbuf, pkgsiz, &tmp_hresp, &pkgoff, &hresp.startMarker[0])) == RSP_OK) {
                pkg_count--;
            }
            abs_count--;
        }
        if (pkg_count != 0)
            ERRPRINT_BOTH("Last parseResponse returned: %d (validPkgs/maxPkgs: %lu/%lu)", ret, validPkgs, maxPkgs);
        ERRETCPLD( abs_count == 0, abs_count );
        ERRETCPLD( pkg_count == 0, pkg_count );
    }

    PARSE_RESPONSE_CLEANUP(pkgbuf, pkgsiz, pkg_count, hresp);

    {
        DWORD maxPkgs = 64;
        for (DWORD i = 0; i < maxPkgs; ++i) {
            hresp.respCode = RC_PING;
            ERRETCP( addPkg(0, 0, &hresp, &pkgbuf, &pkgsiz) == TRUE );
            pkg_count++;
        }
        int ret;
        struct http_resp* tmp_hresp = NULL;
        size_t pkgoff = 0;
        while ((ret = parseResponse(pkgbuf, pkgsiz, &tmp_hresp, &pkgoff, &hresp.startMarker[0])) == RSP_OK) {
            pkg_count--;
        }
        if (pkg_count != 0)
            ERRPRINT_BOTH("Last parseResponse returned: %d (maxPkgs: %lu)", ret, maxPkgs);
        ERRETCPLD( pkg_count == 0, pkg_count );
    }

    PARSE_RESPONSE_CLEANUP(pkgbuf, pkgsiz, pkg_count, hresp);

    {
        hresp.respCode = RC_PING;
        ERRETCP( addRequest(&pkgbuf, &pkgsiz, &hresp) == RSP_OK );
        int ret = -1;
        struct http_resp* tmp_hresp = NULL;
        size_t pkgoff = 0;
        ERRETCPLD( (ret = parseResponse(pkgbuf, pkgsiz, &tmp_hresp, &pkgoff, &hresp.startMarker[0])) == RSP_OK, ret );
    }
    PARSE_RESPONSE_CLEANUP(pkgbuf, pkgsiz, pkg_count, hresp);
    {
        hresp.respCode = 0;
        ERRETCP( addRequest(&pkgbuf, &pkgsiz, &hresp) == RSP_OK );
        int ret = -1;
        struct http_resp* tmp_hresp = NULL;
        size_t pkgoff = 0;
        ERRETCPLD( (ret = parseResponse(pkgbuf, pkgsiz, &tmp_hresp, &pkgoff, &hresp.startMarker[0])) != RSP_OK, ret );
    }
    PARSE_RESPONSE_CLEANUP(pkgbuf, pkgsiz, pkg_count, hresp);

    {
        int abs_count = 0;
        rrcode all_codes[] = RC_ALL;
        DWORD maxPkgs = 64;
        DWORD validPkgs = 0;
        for (DWORD i = 0; i < maxPkgs; ++i) {
            rrcode rc;
            int rnd;
            while ((rnd = __rdtsc()) == 0) {}
            if (rnd % 2 == 0)
                rc = all_codes[ __rdtsc() % SIZEOF(all_codes) ];
            else
                rc = (rrcode)__rdtsc();
            for (DWORD j = 0; j < SIZEOF(all_codes); ++j) {
                if (all_codes[j] == rc) {
                    pkg_count++;
                    validPkgs++;
                    break;
                }
            }
            abs_count++;
            hresp.respCode = rc;
            ERRETCP( addRequest(&pkgbuf, &pkgsiz, &hresp) == RSP_OK );
        }
        int ret;
        struct http_resp* tmp_hresp = NULL;
        size_t pkgoff = 0;
        while (abs_count > 0) {
            if ((ret = parseResponse(pkgbuf, pkgsiz, &tmp_hresp, &pkgoff, &hresp.startMarker[0])) == RSP_OK) {
                pkg_count--;
            }
            abs_count--;
        }
        if (pkg_count != 0)
            ERRPRINT_BOTH("Last parseResponse returned: %d (validPkgs/maxPkgs: %lu/%lu)", ret, validPkgs, maxPkgs);
        ERRETCPLD( abs_count == 0, abs_count );
        ERRETCPLD( pkg_count == 0, pkg_count );
    }

    PARSE_RESPONSE_CLEANUP(pkgbuf, pkgsiz, pkg_count, hresp);

    {
        int abs_count = 0;
        rrcode all_codes[] = RC_ALL;
        DWORD maxPkgs = 64;
        DWORD validPkgs = 0;
        for (DWORD i = 0; i < maxPkgs; ++i) {
            rrcode rc;
            int rnd;
            while ((rnd = __rdtsc()) == 0) {}
            if (rnd % 2 == 0)
                rc = all_codes[ __rdtsc() % SIZEOF(all_codes) ];
            else
                rc = (rrcode)__rdtsc();
            for (DWORD j = 0; j < SIZEOF(all_codes); ++j) {
                if (all_codes[j] == rc) {
                    pkg_count++;
                    validPkgs++;
                    break;
                }
            }
            abs_count++;

            rrsize psiz = __rdtsc() % 512;
            struct http_resp* nresp = calloc(sizeof(*nresp) + pkgsiz, 1);
            memcpy(&nresp->startMarker[0], &hresp.startMarker[0], MARKER_SIZ);
            nresp->pkgsiz = psiz;
            nresp->respCode = rc;
            ERRETCP( addRequest(&pkgbuf, &pkgsiz, nresp) == RSP_OK );
            free(nresp);
        }

        int ret;
        struct http_resp* tmp_hresp = NULL;
        size_t pkgoff = 0;
        while (abs_count > 0) {
            if ((ret = parseResponse(pkgbuf, pkgsiz, &tmp_hresp, &pkgoff, &hresp.startMarker[0])) == RSP_OK) {
                pkg_count--;
            }
            abs_count--;
        }
        if (pkg_count != 0)
            ERRPRINT_BOTH("Last parseResponse returned: %d (validPkgs/maxPkgs: %lu/%lu)", ret, validPkgs, maxPkgs);
        ERRETCPLD( abs_count == 0, abs_count );
        ERRETCPLD( pkg_count == 0, pkg_count );
    }

    PARSE_RESPONSE_CLEANUP(pkgbuf, pkgsiz, pkg_count, hresp);
    return TRUE;
}
