/*
 * WARNING: Any changes in this file require a *FULL* project rebuild!
 *    e.g.: `git clean -df . ; cmake . ; make -j4`
 */

#define _AESDATA_(name, str)     static volatile unsigned char name[] = str
#define _AESSIZE_(name, aesData) static size_t name = (size_t)( (sizeof(aesData)/sizeof(aesData[0]))-1 )

