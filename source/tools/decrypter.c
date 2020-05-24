#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef __MINGW32__
#include <windows.h>
#else
#define __cdecl
#include <string.h>
#endif

#ifndef i386
#error "decrypter does work with 32 bit compilation mode only at the moment"
#endif

#include "crypt.h"
#include "helper.h"


/* see source/decrypter_x86.asm */
__cdecl int decrypt_data(uint32_t* buf, uint32_t siz, uint32_t* iv, uint32_t* key, uint32_t ivkeysiz) __asm__("__decrypt_x86");


int main(int argc, char** argv)
{
  bool verbose = false;

  if (argc != 2) {
    fprintf(stderr, "usage: %s [TESTFILE]\n", argv[0]);
    return -1;
  }

  if (getenv("VERBOSE") != NULL) {
    if (strcmp(getenv("VERBOSE"), "1") == 0) {
      verbose = true;
    } else {
      fprintf(stderr, "%s: quiet mode, activate verbose mode with `export VERBOSE=1`\n", argv[0]);
    }
  }

  /* decrypter test */
  printf("Decrypter........: 0x%p\n", decrypt_data);

  size_t bufsiz = 0;
  char* buf = mapfile(argv[1], &bufsiz);
  if (!buf) {
    return 1;
  }
  printf("buffer size......: 0x%p (%lu)\n", (void*)bufsiz, (long unsigned int)bufsiz);

  uint32_t iv[]  = { xor32_randomkey(), xor32_randomkey(), xor32_randomkey(), xor32_randomkey(), xor32_randomkey() };
  uint32_t key[] = { xor32_randomkey(), xor32_randomkey(), xor32_randomkey(), xor32_randomkey(), xor32_randomkey() };
  size_t ivkeysiz = sizeof(iv)/sizeof(uint32_t);

  printf("\n---------- Crypter ----------\n");
  printf("plain buffer adr.: 0x%p\n", buf);
  printf("iv adr...........: 0x%p\n", &iv[0]);
  printf("key adr..........: 0x%p\n", &key[0]);
  if (verbose) {
    char* bufdata = bintostr(buf, bufsiz, 1, NULL);
    printf("buffer...........: %s\n", bufdata);
    free(bufdata);
  }
  char* ivdata  = bintostr((char*)&iv[0] , sizeof(iv),  1, NULL);
  char* keydata = bintostr((char*)&key[0], sizeof(key), 1, NULL);
  printf("iv...............: %s\n", ivdata);
  printf("key..............: %s\n", keydata);

  uint32_t* xorbuf = calloc( (bufsiz/sizeof(uint32_t)) + ivkeysiz, sizeof(uint32_t));
  memcpy((void*)xorbuf, buf, bufsiz);
  uint32_t xorsiz = xor32n_pcbc_crypt_buf(xorbuf, bufsiz, &iv[0], &key[0], ivkeysiz);
  printf("encryoted buf adr: 0x%p\n", xorbuf);
  printf("encrypted size...: 0x%p (%lu)\n", (void*)xorsiz, (long unsigned int)xorsiz);

  char* plainbuf = calloc(xorsiz, sizeof(char));
  memcpy((void*)plainbuf, (void*)xorbuf, xorsiz);
  xor32n_pcbc_crypt_buf((uint32_t*)plainbuf, xorsiz, &iv[0], &key[0], ivkeysiz);

  if (verbose) {
    printf("xor32n_pcbc......: ");
    char* xordata = bintostr((char*)xorbuf, xorsiz, 1, NULL);
    printf("%s\n", xordata);
    free(xordata);

    printf("plaintext........: ");
    char* plaindata = bintostr((char*)plainbuf, bufsiz, 1, NULL);
    printf("%s\n", plaindata);
    free(plaindata);
  }

  int retval = decrypt_data(xorbuf, xorsiz, &iv[0], &key[0], ivkeysiz);
  printf("\n--------- Decrypter ---------\n");
  printf("retval...........: 0x%p (%d)\n", (void*)retval, retval);
  if (verbose) {
    printf("decrypted........: ");
    char* decpdata = bintostr((char*)xorbuf, bufsiz, 1, NULL);
    printf("%s\n", decpdata);
    free(decpdata);
  }

  if (memcmp(plainbuf, buf, bufsiz) != 0) {
    fprintf(stderr, "%s: c decrypter failed to decrypt data correctly\n", argv[0]);
    return 1;
  }
  if (memcmp(xorbuf, plainbuf, xorsiz) != 0) {
    fprintf(stderr, "%s: asm decrypter failed to decrypt data correctly\n", argv[0]);
    return 1;
  }
  fprintf(stderr, "\n%s: success\n", argv[0]);

  free(plainbuf);
  free(xorbuf);
  free(keydata);
  free(ivdata);

  return 0;
}
