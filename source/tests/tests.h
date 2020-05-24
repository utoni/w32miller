#ifndef TESTS_H_INCLUDED
#define TESTS_H_INCLUDED

#ifndef _RUN_TESTS
#error "_RUN_TESTS has to be defined"
#endif
#include "compat.h"

#include <stdio.h>
#include <libgen.h>


#define MYASSERT_LOGFILE logfile
extern FILE* MYASSERT_LOGFILE;

extern unsigned test_count;
extern unsigned test_faild;

#define ERRPRINT(file, fmt, ...) { \
                        char* __erret_str = strdup(__FILE__); \
                            if (__erret_str != NULL) { \
                                char* __erret_base = basename(__erret_str); \
                                fprintf(file, "%s.%d: " fmt "\n", (__erret_base != NULL ? __erret_base : "NULL"), __LINE__, ##__VA_ARGS__); \
                                free(__erret_str); \
                            } \
                        }
#define ERRPRINT_STDERR(fmt, ...) \
                        ERRPRINT(stderr, fmt, __VA_ARGS__)
#define ERRPRINT_LOGFILE(fmt, ...) \
                        if (MYASSERT_LOGFILE != NULL) { ERRPRINT(MYASSERT_LOGFILE, fmt, __VA_ARGS__); fflush(MYASSERT_LOGFILE); }
#define ERRPRINT_BOTH(fmt, ...) \
                        ERRPRINT(stderr, fmt, __VA_ARGS__) \
                        ERRPRINT_LOGFILE(fmt, __VA_ARGS__)

#define MYASSERT_RETVAL retval
#define MYASSERT_RETVAL_DEF int MYASSERT_RETVAL = 0;
#define MYASSERT_LOG "tests.log"
#define MYASSERT_LOGDEF FILE* MYASSERT_LOGFILE = NULL
#define MYASSERT_INIT \
                        MYASSERT_RETVAL_DEF; \
                        if ((MYASSERT_LOGFILE = fopen(MYASSERT_LOG, "w")) == NULL) { \
                            ERRPRINT_BOTH("Could not open \"%s\" for writing.\n", MYASSERT_LOG); \
                        } else ERRPRINT_BOTH("Logfile-Init: %s", MYASSERT_LOG);

#define MYASSERT_RETURN \
                        fclose(MYASSERT_LOGFILE); \
                        return MYASSERT_RETVAL;

#define MYASSERT(expr) { \
                        ERRPRINT_LOGFILE("MYASSERT: %s", #expr); \
                        if ((expr) != TRUE) { \
                            fprintf_setw(stderr, 50, "%s", #expr); \
                            ERRPRINT_BOTH("FAILED with ERROR: %d", (int)GetLastError()); \
                            MYASSERT_RETVAL++; \
                        } else { \
                            fprintf_setw(stderr, 50, "%s", #expr); \
                            fprintf(stderr, "%s\n", "SUCCEEDED"); \
                        } \
                       }

#define MYASSERT_SILENT(expr) { \
                        ERRPRINT_LOGFILE("MYASSERT_SILENT: %s", #expr); \
                        int outfd = dup(fileno(stdout)); \
                        int stdfd = fileno(stdout); \
                        close(stdfd); \
                        dup2(null_dev, stdfd); \
                        BOOL ret = (expr); \
                        close(stdfd); \
                        dup2(outfd, stdfd); \
                        close(outfd); \
                        if (ret != TRUE) { \
                            fprintf_setw(stderr, 50, "%s", #expr); \
                            ERRPRINT_BOTH("FAILED with ERROR: %d", (int)GetLastError()); \
                        } else { \
                            fprintf_setw(stderr, 50, "%s", #expr); \
                            fprintf(stderr, "%s\n", "SUCCEEDED"); \
                        } \
                       }


#define _ERRETCP(expr)      { test_count++; if ( (expr) != TRUE ) { test_faild++; ERRPRINT_BOTH("(%s) != TRUE", #expr); return FALSE; } }
#define ERRETCP(expr)       { ERRPRINT_LOGFILE("ERRETCP: %s", #expr); _ERRETCP(expr); }
#define ERRETCP_NOLOG(expr) { _ERRETCP(expr); }

#define _ERRETCPDW(expr, val)       { test_count++; if ( (expr) != TRUE ) { test_faild++; ERRPRINT_BOTH("(%s) != TRUE , %s = %lu (0x%lX)", #expr, #val, (unsigned long)val, (unsigned long)val); return FALSE; } }
#define ERRETCPDW(expr, val)        { ERRPRINT_LOGFILE("ERRETCPDW: %s , %s = %lu (0x%lX) (", #expr, #val, (unsigned long)val, (unsigned long)val); _ERRETCPDW(expr, val); }
#define ERRETCPDW_NOLOG(expr, val)  { _ERRETCPDW(expr, val); }

#define _ERRETCPLD(expr, val)       { test_count++; if ( (expr) != TRUE ) { test_faild++; ERRPRINT_BOTH("(%s) != TRUE , %s = %ld (0x%lX)", #expr, #val, (long)val, (unsigned long)val); return FALSE; }   }
#define ERRETCPLD(expr, val)        { ERRPRINT_LOGFILE("ERRETCPL: %s , %s = %ld (0x%lX) (", #expr, #val, (long)val, (unsigned long)val); _ERRETCPDW(expr, val); }
#define ERRETCPLD_NOLOG(expr, val)  { _ERRETCPDW(expr, val); }


extern int null_dev;

char* test_randstring(size_t length);

char* test_randhexstring(size_t length);

int fprintf_setw(FILE *stream, size_t s_maxlen, const char *format, ...);

BOOL test_memmove(void);

BOOL test_realloc(void);

BOOL test_memalign(void);

BOOL test_heap(void);

BOOL test_mem(void);

BOOL test_stdio(void);

BOOL test_math(void);

BOOL test_utils(void);

BOOL test_distorm(void);

BOOL test_aes(void);

BOOL test_crypt(void);

BOOL test_pe(char* filename);

BOOL test_http(void);

#endif // TESTS_H_INCLUDED
