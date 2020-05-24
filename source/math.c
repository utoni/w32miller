#include "compat.h"
#include "math.h"


uint64_t __udivmoddi4(uint64_t num, uint64_t den, uint64_t * rem_p)
{
    uint64_t quot = 0, qbit = 1;

    if (den == 0) {
	asm volatile ("int $0");
	return 0;		/* If trap returns... */
    }

    /* Left-justify denominator and count shift */
    while ((int64_t) den >= 0) {
	den <<= 1;
	qbit <<= 1;
    }

    while (qbit) {
	if (den <= num) {
	    num -= den;
	    quot += qbit;
	}
	den >>= 1;
	qbit >>= 1;
    }

    if (rem_p)
	*rem_p = num;

    return quot;
}

/* slightly modified version from
 *   https://code.google.com/p/embox/source/browse/trunk/embox/src/lib/gcc
 *   _thx_
 */

UINT64 __udivdi3(UINT64 num, UINT64 den)
{
    UINT64 result = 0;
    int steps;

    if (den == 0)
    {
        return 0;
    }

    steps = 0;
    result = 0;

    while (!(den & 0x8000000000000000))
    {
        den <<= 1;
        ++steps;
    }

    do
    {
        result <<= 1;
        if (num >= den)
        {
            result |= 1;
            num -= den;
        }
        den >>= 1;
    }
    while (steps--);

    return result;
}

INT64 __divdi3(INT64 num, INT64 den)
{
    INT64 quot;
    int neg;

    num = num < 0 ? (neg = 1, -num) : (neg = 0, num);
    den = den < 0 ? (neg ^= 1, -den) : den;

    quot = __udivdi3(num, den);

    return neg ? -quot : quot;
}

INT64 __moddi3(INT64 num, INT64 den)
{
    INT64 rem;
    int neg;

    num = num < 0 ? (neg = 1, -num) : (neg = 0, num);
    den = den < 0 ? (neg ^= 1, -den) : den;

    rem = __umoddi3(num, den);

    return neg ? -rem : rem;
}

UINT64 __umoddi3(UINT64 num, UINT64 den)
{
    int steps;

    if (den == 0)
    {
        return 0;
    }

    steps = 0;

    while (!(den & 0x8000000000000000))
    {
        den <<= 1;
        ++steps;
    }

    do
    {
        if (num >= den)
        {
            num -= den;
        }
        den >>= 1;
    }
    while (steps--);

    return num;
}

size_t __pow(size_t x, size_t n)
{
    if (n > 0) {
      return x*__pow(x, n-1);
    } else return 1;
}
