#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


/* see source/loader_x86.asm */
int loader_start() __asm__("__ldr_start");


#pragma GCC diagnostic ignored "-Wreturn-type"
extern int getKernelBase(void) __asm__("getKernelBase");

static int __attribute__ ((unused))
__dummy_getKernelBase()
{
  __asm__ __volatile__(
    ".intel_syntax noprefix\n"
    ".global getKernelBase\n"
    "getKernelBase:\n"
    "nop; nop; nop\n\t"
    "mov eax,[fs:0x30]\n\t"
    "mov eax,[eax+0x0c]\n\t"
    "mov eax,[eax+0x14]\n\t"
    "mov eax,[eax]; mov eax,[eax]\n\t"
    "mov eax,[eax+0x10]\n\t"
    "ret\n\t"
    "nop; nop; nop\n\t"
    ".att_syntax\n"
  );
}
#pragma GCC diagnostic warning "-Wreturn-type" /* disable "non void function doesnt return anything"-error */

extern FARPROC myGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
  return GetProcAddress(hModule, lpProcName);
}

extern HMODULE WINAPI myGetModuleHandle(LPCTSTR lpModuleName) {
  return GetModuleHandle(lpModuleName);
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
  } else if (argc == 1) {
    printf("You can set my termination time with `%s [WAIT_TIME]`\n\n", argv[0]);
  }

  printf("getKernelBase....: 0x%p\n", (char*)getKernelBase());

  __asm__ __volatile__(
    "nop; nop; nop; nop; nop;"
  );
  HMODULE k32 = myGetModuleHandle("kernel32.dll");
  __asm__ __volatile__(
    "nop; nop; nop; nop; nop;"
  );
  printf("Kernel32.dll.....: 0x%p\n", k32);
  __asm__ __volatile__(
    "nop; nop; nop; nop; nop;"
  );
  printf("GetProcAddr......: 0x%p\n", GetProcAddress);
  printf("VirtualAlloc.....: 0x%p\n", myGetProcAddress(k32, "VirtualAlloc"));
  printf("IsBadReadPtr.....: 0x%p\n", myGetProcAddress(k32, "IsBadReadPtr"));

  __asm__ __volatile__(
    "nop; nop; nop; nop; nop;"
  );

#ifdef _MILLER_IMAGEBASE
  /* force relocation */
  LPVOID vpointer = VirtualAlloc((LPVOID)_MILLER_IMAGEBASE, 0x1000, MEM_RESERVE, PAGE_READWRITE);
  if (!vpointer) {
    printf("VirtualAlloc,,,..: %ld\n", GetLastError());
  } else {
    printf("Ptr-alloc'd......: 0x%p\n", vpointer);
  }
#else
  printf("WARNING..........: Ptr-alloc disabled ( missing macro `-D_MILLER_IMAGEBASE=[HEX-VALUE]` )\n");
#endif

  /* loader test */
  printf("Loader...........: 0x%p\n", loader_start);
  printf("------------ EoL ------------\n");
  int retval = loader_start();
  sleep(dwWait);
  printf("-----------------------------\n");
  printf("Loader init......: 0x%p (%d)\n", (void*)retval, retval);
  printf("error............: 0x%p (%ld)\n", (void*)GetLastError(), GetLastError());

  return retval;
}
