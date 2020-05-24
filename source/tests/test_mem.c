#include "tests.h"

#include "utils.h"


BOOL test_memalign(void)
{
    DWORD addr = 0x41414141;
    DWORD size = 512;
    DWORD algn = 512;

    ERRETCP( XMemAlign(size, algn, addr) == addr+size );
    size++;
    ERRETCP( XMemAlign(size, algn, 0) == 1024 );
    ERRETCP( XMemAlign(size, algn, addr) == addr+1024 );
    return TRUE;
}
