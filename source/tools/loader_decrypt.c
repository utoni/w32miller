#include "compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "utils.h"
#include "helper.h"
#include "aes.h"
#include "xor_strings.h"
#include "aes_strings_gen.h"
#include "loader_x86_crypt.h"


_AESDATA_(ldrdata, LOADER_SHELLCODE);
_AESSIZE_(ldrsiz, ldrdata);
static const size_t real_ldrsiz = LOADER_SHELLCODE_SIZE;

_AESDATA_(ldrdbgdata, LOADER_SHELLCODE_DEBUG);
_AESSIZE_(ldrdbgsiz, ldrdbgdata);
static const size_t real_ldrdbgsiz = LOADER_SHELLCODE_DEBUG_SIZE;


int main(int argc, char** argv)
{
  (void)argc;
  aes_init();

  size_t pSiz = 0;
  aes_ctx_t* ctx = aes_alloc_ctx((unsigned char*)LDR_KEY, LDR_KEYSIZ);

  BYTE* ldr = (BYTE*)aes_crypt_s(ctx, (char*)ldrdata, (size_t)ldrsiz, &pSiz, false);

  char* hexout = bintostr((char*)ldr, real_ldrsiz, 1, NULL);
  printf("%s [DECRYPTED]: %u bytes\n%s\n", argv[0], real_ldrsiz, hexout);

  free(ldr);
  free(hexout);

  hexout = bintostr((char*)ldrdata, ldrsiz, 1, NULL);
  printf("%s [ENCRYPTED]: %u bytes\n%s\n", argv[0], ldrsiz, hexout);
  free(hexout);

  ldr = (BYTE*)aes_crypt_s(ctx, (char*)ldrdbgdata, (size_t)ldrdbgsiz, &pSiz, false);

  hexout = bintostr((char*)ldr, real_ldrdbgsiz, 1, NULL);
  printf("%s [DECRYPTED]: %u bytes\n%s\n", argv[0], real_ldrdbgsiz, hexout);

  free(ldr);
  free(hexout);

  hexout = bintostr((char*)ldrdata, ldrdbgsiz, 1, NULL);
  printf("%s [ENCRYPTED]: %u bytes\n%s\n", argv[0], ldrdbgsiz, hexout);
  free(hexout);

  aes_free_ctx(ctx);
  return 0;
}
