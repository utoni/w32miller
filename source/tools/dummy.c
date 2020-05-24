#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


int subroutine(void* ptr, int d)
{
    return (int)ptr+d+1;
}

int main(int argc, char** argv)
{
    DWORD dwWait = 2;

    if (argc > 1 && argc != 2) {
        printf("usage: %s [WAIT_TIME]\n", argv[0]);
        abort();
    } else if (argc == 2) {
        errno = 0;
        dwWait = strtoul(argv[1], NULL, 10);
        if (errno != 0)
            dwWait = 2;
    }

    printf("%s", "Hi, I'm a useless dummy like the guy who coded me.\n");
    printf("Waiting %lu seconds ..\n", dwWait);
    sleep(dwWait);
    printf("%s", "Dummy done.\n");
    if (subroutine(NULL, 1) == 2) {
        return 0;
    } else return 1;
}
