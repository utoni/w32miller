#include "compat.h"
#include "irc.h"


int main(int argc, char** argv)
{
    void* loadlib = LoadLibraryA;
    void* getproc = GetProcAddress;

    (void) argc;
    if (!bInitCompat(LoadLibraryA("KERNEL32.dll"), getproc))
        return -1;

    COMPAT(printf)("LoadLibraryA.....: 0x%p\n", loadlib);
    COMPAT(printf)("GetProcAddress...: 0x%p\n", getproc);
    COMPAT(printf)("WSAStartup.......: 0x%p\n", WSAStartup);

    int ret;
    if ((ret = initSocket(loadlib, getproc)) != 0) {
        COMPAT(printf)("%s: initSocket(...) failed with: %d\n", argv[0], ret);
        return 1;
    }

    if ((ret = ircLoop("muzzling", "#blkhtm", "dreamhack.se.quakenet.org", "6667")) != 0) {
        COMPAT(printf)("%s: ircLoop() returned: %d\n", argv[0], ret);
    }
    switch (ret) {
        case WSAHOST_NOT_FOUND:
            COMPAT(printf)("%s: Host not found.\n", argv[0]);
            break;
        case WSAETIMEDOUT:
            COMPAT(printf)("%s: Connection timed out.\n", argv[0]);
            break;
    }

    return 0;
}
