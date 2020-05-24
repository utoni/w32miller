#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <string.h>

#include <sys/stat.h>

#ifdef __MINGW32__
#include <windows.h>
#else
#include <sys/mman.h> /* mmap - not available on windoze */
#endif

#include "helper.h"

#ifdef _USE_PYTHON
#undef _POSIX_C_SOURCE
#undef _XOPEN_SOURCE
#include <Python.h>
#endif


static const char hextable[] = "0123456789ABCDEF";


#ifdef _USE_PYTHON
void* MyPyMem_Calloc(size_t n, size_t s)
{
    void* ptr = PyMem_Malloc(n*s);
    if (ptr)
        memset(ptr, '\0', n*s);
    return ptr;
}
#endif

char* mapfile(const char* path, size_t* mapsizptr)
{
    /* TODO: MINGW alternative should to exactly the same as the linux one! (map file to memory without duplicating the mmap's buffer) */
#ifdef __MINGW32__
    HANDLE hfile = CreateFile(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hfile == INVALID_HANDLE_VALUE)
        return NULL;
    if (SetFilePointer(hfile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
        return NULL;
    *mapsizptr = GetFileSize(hfile, NULL);
    if (*mapsizptr == INVALID_FILE_SIZE)
        return NULL;
    char* buf = calloc(*mapsizptr, sizeof(char));
    DWORD szread = 0;
    if (!buf)
        return NULL;
    if (ReadFile(hfile, buf, *mapsizptr, &szread, NULL) != TRUE) {
        free(buf);
        return NULL;
    }
    CloseHandle(hfile);
    return buf;
#else
    int fd = open(path, O_RDWR);
    if (fd == -1)
        return NULL;
    struct stat sb;
    if (fstat(fd, &sb) == -1)
        return NULL;
    char* mapd = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapd == MAP_FAILED)
        return NULL;
    *mapsizptr = sb.st_size;
    close(fd);
    return mapd;
#endif
}

ssize_t writebuf(const char* path, unsigned char* buf, size_t siz)
{
    int ffd = open(path, O_WRONLY | O_CREAT | O_TRUNC,
                   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    ssize_t wrt = write(ffd, buf, siz);
    close(ffd);
    return wrt;
}

char* bintostr(const char* buf, size_t siz, size_t delim, size_t *strlenptr)
{
    register size_t i;
    size_t allocLen = ( delim > 0 ? (int)(siz/delim) : 1 ) + siz*2;
    char* result = calloc(allocLen+1, sizeof(char));
    char tmp[4];

    tmp[3] = '\0';
    for (i = 0; i < siz; ++i) {
        register unsigned char halfByte = buf[i] >> 4;
        tmp[0] = hextable[halfByte%16];
        halfByte = buf[i] & 0x0F;
        tmp[1] = hextable[halfByte%16];
        tmp[2] = '\0';
        if (delim>0 && i%delim==delim-1)
            tmp[2] = ' ';
        strcat(result, tmp);
    }
    result[allocLen] = '\0';
    if (strlenptr) {
        *strlenptr = allocLen;
    }
    return result;
}

void printrimmed(char* str, size_t siz, size_t charsperline, bool printlinenmb)
{
    if (charsperline == 0) {
        printf("%s\n", str);
    } else {
        unsigned long ln = 0;
        for (size_t i = 0; i < siz; i+=charsperline) {
            if (printlinenmb) {
                printf("%04lu: ", ln++);
            }
            size_t psiz = (i+1 < siz-charsperline ? charsperline : siz-i);
            printf("%.*s\n", (int)psiz, (str + i));
        }
    }
}

void printbytebuf(char* buf, size_t siz, size_t charsperline, bool printlinenmb)
{
    size_t hexlen = 0;
    char* hexbuf = bintostr(buf, siz, 1, &hexlen);
    printrimmed(hexbuf, hexlen, charsperline, printlinenmb);
    free(hexbuf);
}

char *strnstr(const char *haystack, const char *needle, size_t len)
{
    int i;
    size_t needle_len;

    if (0 == (needle_len = strnlen(needle, len)))
        return (char *)haystack;

    for (i=0; i<=(int)(len-needle_len); i++) {
        if ((haystack[0] == needle[0]) &&
          (0 == strncmp(haystack, needle, needle_len)))
            return (char *)haystack;
        haystack++;
    }
    return NULL;
}
