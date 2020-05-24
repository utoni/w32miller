#ifndef HELPER_H_INCLUDED
#define HELPER_H_INCLUDED

#include <stdbool.h>
#include <stdlib.h>

#ifdef _USE_PYTHON
/* Python header files redefine some macros */
#undef _POSIX_C_SOURCE
#undef _XOPEN_SOURCE
#include <Python.h> /* obligatory */

#undef calloc
#undef malloc
#undef realloc
#undef free
#define calloc  MyPyMem_Calloc
#define malloc  PyMem_Malloc
#define realloc PyMem_Realloc
#define free    PyMem_Free
void* MyPyMem_Calloc(size_t n, size_t s);
#endif /* _USE_PYTHON */


char* mapfile(const char* path, size_t* mapsizptr);

ssize_t writebuf(const char* path, unsigned char* buf, size_t siz);

char* bintostr(const char* buf, size_t siz, size_t delim, size_t *strlenptr);

void printrimmed(char* str, size_t siz, size_t charsperline, bool printlinenmb);

void printbytebuf(char* buf, size_t siz, size_t charsperline, bool printlinenmb);

char *strnstr(const char *haystack, const char *needle, size_t len);

#endif
