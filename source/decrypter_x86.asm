; Module:  decrypter_x86.asm
; Author:  Toni <matzeton@googlemail.com>
; Purpose: 1. decrypt a buffer encrypted with xor32npcbc

%ifndef _LDR_SECTION
%error "expected _LDR_SECTION to be defined"
%endif
SECTION _LDR_SECTION
GLOBAL __decrypt_x86

EBP_BUFF  EQU   0x08
EBP_SIZE  EQU   0x0c
EBP_IVPT  EQU   0x10
EBP_KEYP  EQU   0x14
EBP_IVKY  EQU   0x18

; xor32n_pcbc decryption routine
; arguments: [ebp + 0x08] = buffer_ptr32
;            [ebp + 0x0c] = size_u32
;            [ebp + 0x10] = iv_ptr32
;            [ebp + 0x14] = key_ptr32
;            [ebp + 0x18] = ivkeysize
; modifies : eax, ebx, ecx, edx, esi, edi
; return   : eax = FALSE if error, non-zero if success
__decrypt_x86:
  ; new stack frame
  push ebp
  mov ebp,esp
  ; check if buffer has a valid size
  xor edx,edx           ; clear remainder
  xor ecx,ecx           ; clear divisor
  mov eax,[ebp + 0x0c]
  mov byte cl,0x04
  div ecx               ; size_u32 % sizeof(uint32)
  xor eax,eax
  cmp edx,eax           ; remainder == 0 ?
  jnz __decrypt_failed
  ; uint32_t prev[ivkeysiz];
  mov ecx,[ebp + 0x18]  ; ivkeysize
  ; calculate and reserve stack space
  xor edx,edx
  xor eax,eax
  mov al,0x04
  mul ecx
  sub esp,eax           ; make space for ivkeysiz*sizeof(uint32)
  ; init prev[i] with iv[i]
  mov edx,[ebp + 0x10]  ; iv_ptr32
  __decrypt_prev:       ; ecx = ivkeysize
  mov eax,[ebp + 0x18]  ; ivkeysize
  sub eax,ecx           ; ivkeysize - ecx
  mov edi,[edx + eax*4]
  mov dword [esp + eax*4],edi
  loop __decrypt_prev
  ; size_u32 / sizeof(uint32)
  mov ecx,[ebp + 0x0c]  ; size_u32
  shr ecx,0x02          ; / sizeof(uint32)
  ; main decrypt loop
  mov edi,ecx           ; edi = count
  __decrypt_loop:       ; ecx = count-i
  ; calculate i
  mov eax,edi
  sub eax,ecx           ; count-(count-i)
  mov esi,eax           ; esi = i
  ; calculate iv/key i
  xor edx,edx           ; clear remainder
  mov ebx,[ebp + 0x18]  ; ivkeysize
  div ebx               ; i % ivkeysize
  mov ebx,edx           ; ebx = iv/key i
  ; get buffer content
  mov edx,[ebp + 0x08]  ; buffer_ptr32
  mov edx,[edx + esi*4] ; edx = buf[i]
  ; decrypt content
  mov eax,[ebp + 0x14]
  mov eax,[eax + ebx*4] ; eax = key[iv/key i]
  xor eax,edx           ; tmp = xor32_crypt(buf[i], key[iv/key i])
  xor eax,[esp + ebx*4] ; plain = xor32_crypt(tmp, prev[iv/key i])
  push ebx
  mov ebx,[ebp + 0x08]  ; buffer_ptr32
  mov [ebx + esi*4],eax
  pop ebx
  ; calculate prev[iv/key i]
  xor eax,edx           ; prev[iv/key i] = xor32_crypt(plain, crypt)
  mov [esp + ebx*4],eax
  loop __decrypt_loop
  ; cleanup stack
  xor edx,edx
  xor eax,eax
  mov ecx,[ebp + 0x18]
  mov al,0x04
  mul ecx
  add esp,eax
  ; return value (size of buffer)
  mov eax,[ebp + 0x0c]
  ; restore old frame
  pop ebp
  ret
__decrypt_failed:
  pop ebp
  xor eax,eax
  ret

