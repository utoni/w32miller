#ifndef IRC_H_INCLUDED
#define IRC_H_INCLUDED

#include "compat.h"


#define R_BUFSIZ 512
#define S_BUFSIZ 256
#define S_TIMEOUT 60000

typedef struct addrinfo {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    size_t ai_addrlen;
    char *ai_canonname;
    struct sockaddr *ai_addr;
    struct addrinfo *ai_next;
} ADDRINFOA, *PADDRINFOA;


int initSocket(LoadLibraryFunc loadlib, GetProcAddressFunc getproc);

int shutSocket(void);

int ircRaw(const char* fmt, ...);

int ircPrivmsg(const char* target, size_t totalSiz, const char* fmt, ...);

int ircPrivmsgBinary(char* target, const unsigned char* buf, size_t siz);

int ircLoop(const char* nick, const char* channel, const char* host, const char* port);

#endif /* IRC_H_INCLUDED */
