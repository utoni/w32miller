#include "compat.h"
#include "tests.h"
#include "utils.h"

#include <unistd.h>
#include <signal.h>


int null_dev = -1;
static FILE* null_file = NULL;
MYASSERT_LOGDEF;
unsigned test_count = 0;
unsigned test_faild = 0;


void sigsegv_handler(int signal)
{
    if (signal == SIGSEGV) {
        ERRPRINT_BOTH("%s", "***** ACCESS VIOLATION *****");
        fclose(null_file);
        fclose(MYASSERT_LOGFILE);
        exit(1);
    }
}

int main(int argc, char** argv)
{
    fprintf(stderr, "Running TESTS ..\n\n");

    (void)argc;
    if (signal(SIGSEGV, sigsegv_handler) == SIG_ERR) {
        fprintf(stderr, "Could not setup a signal handler for memory acces violations!\n");
    }

    if (bInitCompat( LoadLibraryA(TEXT("KERNEL32.dll")), GetProcAddress ) != TRUE) {
      fprintf(stderr, "bInitCompat(...) failed!\n");
      return 1;
    }

    const char* null_devname = "nul";
    null_file = fopen (null_devname, "w");
    if (null_file == NULL) {
        fprintf(stderr, "Could not open windows NULL device: %s", null_devname);
    } else null_dev = _fileno(null_file);

    MYASSERT_INIT;
    MYASSERT(test_math());
    MYASSERT(test_utils())
    MYASSERT(test_heap());
    MYASSERT(test_mem());
    MYASSERT(test_memalign());
    MYASSERT(test_aes());
    MYASSERT(test_crypt());
    MYASSERT(test_distorm());
    MYASSERT(test_stdio());
    MYASSERT(test_pe(argv[0]));
    MYASSERT(test_http());

    MYASSERT_SILENT( (puts("puts(...)\n") == 0) );
    MYASSERT_SILENT( (__xputs("__xputs(...)\n") > 0) );

    static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#'?!";
    char* rndstr = __randstring(4096, charset);
    MYASSERT_SILENT( (__xprintf("---%s---\n", rndstr) > 0) );
    COMPAT(free)(rndstr);

    if (MYASSERT_RETVAL == 0) {
        ERRPRINT_BOTH("SUCCESS | TESTS: %u", (unsigned)test_count);
    } else {
        ERRPRINT_BOTH("LAST FAILED with %d | FAILED/TESTS: %u/%u", MYASSERT_RETVAL, (unsigned)test_faild, (unsigned)test_count);
    }

    MYASSERT_RETURN;
}

char* test_randstring(size_t length)
{

    static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#'?!";
    return __randstring(length, charset);;
}

char* test_randhexstring(size_t length)
{
    static char hcharset[] = "0123456789abcdef";
    return __randstring(length, hcharset);
}

int fprintf_setw(FILE *stream, size_t s_maxlen, const char *format, ...)
{
    int ret;
    static char tmp[BUFSIZ];
    va_list va;
    va_start(va, format);

    ret = vsnprintf(tmp, BUFSIZ, format, va);
    if (ret > 0 && (size_t)ret < s_maxlen && ret+s_maxlen < BUFSIZ)
    {
        for (size_t i = ret; i < s_maxlen; ++i)
            tmp[i] = '.';
    }
    ret = fprintf(stream, "%s", tmp);

    va_end(va);
    return ret;
}
