#ifndef MATH_H_INCLUDED
#define MATH_H_INCLUDED

#include <stdlib.h>
#include <stdint.h>

uint64_t __udivmoddi4(uint64_t num, uint64_t den, uint64_t * rem_p);

uint64_t __umoddi3(uint64_t num, uint64_t den);

int64_t  __moddi3(int64_t num, int64_t den);

uint64_t __udivdi3(uint64_t num, uint64_t den);

int64_t  __divdi3(int64_t num, int64_t den);

size_t __pow(size_t x, size_t n);

#endif // MATH_H_INCLUDED
