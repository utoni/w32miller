#ifndef LOG
#define LOG

#ifdef _DEBUG
#define EMBED_BREAKPOINT \
    __asm volatile("nop; int3; nop;")
#else
#define EMBED_BREAKPOINT
#endif

#if defined(_DEBUG) || defined(_PRE_RELEASE)
#define LOG_MARKER { COMPAT(printf)("%s.%d: Marker!\n", __FILE__, __LINE__); }
#define PRINT_BYTES(buf, siz, delim) \
    { \
        char* result = __xbintostr(buf, siz, delim); \
        puts(result); \
        COMPAT(free)(result); \
    }
#else
#define LOG_MARKER {}
#define PRINT_BYTES(x,y,z) {}
#endif

#endif // LOG_H
