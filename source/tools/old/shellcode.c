
#include <windows.h>

volatile const char *ShellCode __asm__("ShellCode") = ("\x6A\x00\x52\x53\x6A\x00\x89\xCB\xFF\xD3\xC3");
volatile const char *lol __asm__("lol") = "LOLDUDE";
volatile const char *lol2 __asm__("lol2") = "O_O";

typedef void (*MsgBoxFunc)(char*);


void run_test_shellcode(void)
{
  volatile static MsgBoxFunc MsgBoxA __asm__("kurwa") __attribute__((unused));

  MsgBoxA = (MsgBoxFunc) GetProcAddress(LoadLibrary("user32.dll"),"MessageBoxA");
  /* execute code in .text AND .rdata segment */
  __asm__(
      ".intel_syntax noprefix\n"
      "mov ecx, kurwa\n\t"
      "mov edx, [lol]\n\t"
      "mov ebx, [lol2]\n\t"
      "mov esi, ShellCode\n\t"
      "call esi\n\t"
      ".att_syntax\n"
  );

  /* execute code in .text segment ONLY */
  __asm__(
      ".intel_syntax noprefix\n"
      "mov ecx, kurwa\n\t"
      "push 0x0\n\t"
      "push [lol]\n\t"
      "push [lol2]\n\t"
      "push 0x0\n\t"
      "mov ebx,ecx\n\t"
      "call ebx\n\t"
      ".att_syntax\n"
  );
}

int main(int argc, char *argv[])
{
  if (argc == 1)
    run_test_shellcode();
  return 0;
}
