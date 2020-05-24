/* modified (from http://securityxploded.com/memory-execution-of-executable.php) */
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "loader.h"

#define DEREF_32( name )*(DWORD *)(name)


static volatile PVOID kernel32 asm("__kernel32") = NULL;
static volatile PVOID getproc asm("__getproc") = NULL;
static volatile DWORD EntryAddr asm("__EntryAddr");
static volatile PVOID memalloc asm("__memalloc") = NULL;
static volatile PVOID ldr_ptr asm("__ldr") = NULL;

static volatile struct loader_x86_data ldr;
static volatile DWORD size = 0x0;
static volatile PVOID vpointer = NULL;

static volatile DWORD retval asm("__retval") = -1;


int main(int argc, char *argv[])
{
    if (argc != 2 && argc != 3 && argc != 4) {
        fprintf(stderr, "usage: %s path-to-dynamic-library [preferred-Virtual-Address] [wait-time]\n", argv[0]);
        return -1;
    }

    DWORD dwWait = 2;

    if (argc == 4) {
        errno = 0;
        dwWait = strtoul(argv[3], NULL, 10);
        if (errno != 0)
            dwWait = 2;
    }

    BOOL doAllocAt = FALSE;
    PVOID allocPtr = NULL;
    if (argc >= 3) {
        doAllocAt = TRUE;
        char* errch = NULL;
        allocPtr = (PVOID)strtoul(argv[2], &errch, 16);
    }

    HANDLE handle;
    HINSTANCE laddress;
    LPSTR libname;
    DWORD byteread;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_SECTION_HEADER section;
    DWORD dwValueA;
    DWORD dwValueB;
    DWORD dwValueC;
    DWORD dwValueD;

    // read the file
    printf("Reading file..\n");
    handle = CreateFile(argv[1],GENERIC_READ,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
    if (handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "%s: file(%s) does not exist or is not readable\n", argv[0], argv[1]);
        return -1;
    }

    // get the file size
    size = GetFileSize(handle,NULL);
    if (size <= 0) {
        fprintf(stderr, "%s: invalid file(%s) size\n", argv[0], argv[1]);
        return -1;
    }

    // Allocate the space
    vpointer = VirtualAlloc(NULL,size,MEM_COMMIT,PAGE_READWRITE);

    // read file on the allocated space
    ReadFile(handle,vpointer,size,&byteread,NULL);
    CloseHandle(handle);
    printf("File loaded into memory ..\n");
    printf("address............: 0x%X (%lu)\n", (unsigned int)vpointer, (long unsigned int)vpointer);
    printf("size...............: 0x%X (%lu)\n", (unsigned int)size, size);
    printf("Parse PE-Header ..\n");

    // read NT header of the file
    nt = (PIMAGE_NT_HEADERS)((PCHAR)vpointer + ((PIMAGE_DOS_HEADER)vpointer)->e_lfanew);
    printf("e_lfanew...........: 0x%X (%ld)\n", (unsigned int)((PIMAGE_DOS_HEADER)vpointer)->e_lfanew, ((PIMAGE_DOS_HEADER)vpointer)->e_lfanew);
    handle = GetCurrentProcess();

    // get VA of entry point
    printf("AddressOfEntryPoint: 0x%X (%ld)\n", (unsigned int)nt->OptionalHeader.AddressOfEntryPoint, nt->OptionalHeader.AddressOfEntryPoint);
    printf("ImageBase..........: 0x%X (%ld)\n", (unsigned int)nt->OptionalHeader.ImageBase, nt->OptionalHeader.ImageBase);
    printf("SizeOfImage........: 0x%X (%ld)\n", (unsigned int)nt->OptionalHeader.SizeOfImage, nt->OptionalHeader.SizeOfImage);
    printf("SizeOfHeaders......: 0x%X (%ld)\n", (unsigned int)nt->OptionalHeader.SizeOfHeaders, nt->OptionalHeader.SizeOfHeaders);
    printf("SizeOptionalHeader.: 0x%X (%d)\n", (unsigned int)nt->FileHeader.SizeOfOptionalHeader, nt->FileHeader.SizeOfOptionalHeader);

    // Allocate the space with Imagebase as a desired address allocation request
    memalloc = VirtualAllocEx(
                         handle,
                         (doAllocAt == FALSE ? (LPVOID)nt->OptionalHeader.ImageBase : allocPtr),
                         nt->OptionalHeader.SizeOfImage,
                         MEM_RESERVE | MEM_COMMIT,
                         PAGE_EXECUTE_READWRITE
                     );

    // Check for NULL (esp. if the user wants to chooose a specific VA)
    if (!memalloc) {
        printf("FATAL: VirtualAllocEx failed with %d\n", (int)GetLastError());
        exit(1);
    }
    EntryAddr = (DWORD)memalloc + nt->OptionalHeader.AddressOfEntryPoint;

    // Write headers on the allocated space
    WriteProcessMemory(handle,
                       memalloc,
                       vpointer,
                       nt->OptionalHeader.SizeOfHeaders,
                       0
                      );


    // write sections on the allocated space
    section = IMAGE_FIRST_SECTION(nt);
    printf("sizeof(section)....: 0x%X (%u)\n", sizeof(IMAGE_SECTION_HEADER), sizeof(IMAGE_SECTION_HEADER));
    printf("FirstSectionRVA....: 0x%X (%ld)\n", (unsigned int)section[0].VirtualAddress, section[0].VirtualAddress);
    printf("FirstSectionPTR....: 0x%X (%ld)\n", (unsigned int)section[0].PointerToRawData, section[0].PointerToRawData);
    if ((unsigned int)memalloc != (unsigned int)nt->OptionalHeader.ImageBase) {
        printf("Allocated memory block does not start at DLL image base!\n"
               " -> 0x%X != 0x%X\n", (unsigned int)memalloc, (unsigned int)nt->OptionalHeader.ImageBase);
    }

    for (ULONG i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        WriteProcessMemory(
            handle,
            (PCHAR)memalloc + section[i].VirtualAddress,
            (PCHAR)vpointer + section[i].PointerToRawData,
            section[i].SizeOfRawData,
            0
        );
    }

    if (*(DWORD*)&(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]) != 0x00000000)
    {
        // read import dirctory, if exists
        dwValueB = (DWORD) &(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);

        // get the VA
        dwValueC = (DWORD)(memalloc) +
                   ((PIMAGE_DATA_DIRECTORY)dwValueB)->VirtualAddress;

        while(((PIMAGE_IMPORT_DESCRIPTOR)dwValueC)->Name)
        {
            // get DLL name
            libname = (LPSTR)((DWORD)(memalloc) +
                              ((PIMAGE_IMPORT_DESCRIPTOR)dwValueC)->Name);

            // Load dll
            laddress = LoadLibrary(libname);

            // get first thunk, it will become our IAT
            dwValueA = (DWORD)(memalloc) +
                       ((PIMAGE_IMPORT_DESCRIPTOR)dwValueC)->FirstThunk;

            // resolve function addresses
            while(DEREF_32(dwValueA))
            {
                dwValueD = (DWORD)(memalloc) + DEREF_32(dwValueA);
                // get function name
                LPSTR Fname = (LPSTR)((PIMAGE_IMPORT_BY_NAME)dwValueD)->Name;
                // get function addresses
                DEREF_32(dwValueA) = (DWORD)GetProcAddress(laddress,Fname);
                dwValueA += 4;
            }

            dwValueC += sizeof( IMAGE_IMPORT_DESCRIPTOR );
        }
    } else printf("No Import Table found, nothing to import ..\n");

    memset((void*)&ldr, '\0', sizeof(ldr));
    ldr.ptrToDLL = (uint32_t)vpointer;
    ldr.sizOfDLL = size;
    unsigned char marker[] = { _LOADER_ENDMARKER };
    memcpy((void*)&ldr.endMarker, &marker[0], sizeof(ldr.endMarker));

    ldr_ptr = (volatile PVOID) &ldr;
    kernel32 = LoadLibraryA("KERNEL32.dll");
    getproc = GetProcAddress((void*)kernel32, "GetProcAddress");

    printf("Calling DLL AdrOfEntry ..\n");
    // call the entry point :: here we assume that everything is ok.
     asm volatile(
        ".intel_syntax noprefix\n"
        "pushad\n\t"
        "pushfd\n\t"
        "mov ebx,0xdeadbeef\n\t"
        "mov ecx,[__getproc]\n\t"
        "mov edx,[__kernel32]\n\t"
        "mov edi,__memalloc\n\t"
        "mov esi,__ldr\n\t"
        "push 0x00000000\n\t"
        "call [__EntryAddr]\n\t"
        "pop esi\n\t"
        "mov [__retval],eax\n\t"
        "popfd\n\t"
        "popad\n\t"
        ".att_syntax\n"
    );

    sleep(dwWait);
    printf("DLL returned: %X (%d)\n", (unsigned int)retval, (int)retval);
    printf("GetLastError: 0x%X (%ld)\n", (unsigned int)GetLastError(), GetLastError());

    return retval;
}
