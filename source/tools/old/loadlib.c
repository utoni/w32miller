#include <windows.h>
#include <string.h>

#include "compat.h"

#define MAKE_ORDINAL(val) (val & 0xffff)
#define ROUND(n, r) (((n + (r - 1)) / r) * r)

#define GET_NT_HEADERS(module) ((IMAGE_NT_HEADERS *)((char *)module + ((IMAGE_DOS_HEADER *)module)->e_lfanew))

typedef BOOL (WINAPI *DllMainFunc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

static void free_imp_by_range(void *module,
                              IMAGE_IMPORT_DESCRIPTOR *begining,
                              IMAGE_IMPORT_DESCRIPTOR *end);
void *get_proc_address(HMODULE module, const char *proc_name);


DWORD rva_to_raw(DWORD rva, IMAGE_NT_HEADERS *nt_headers)
{
    WORD nsections;
    IMAGE_SECTION_HEADER *sec_hdr = (IMAGE_SECTION_HEADER *)((char *)nt_headers + sizeof(IMAGE_NT_HEADERS));

    for (nsections = 0; nsections < nt_headers->FileHeader.NumberOfSections; nsections++)
    {
        if (rva >= sec_hdr->VirtualAddress &&
                rva < (sec_hdr->VirtualAddress + sec_hdr->Misc.VirtualSize))
            return sec_hdr->PointerToRawData + (rva - sec_hdr->VirtualAddress);
        sec_hdr++;
    }
    return 0;
}

static int is_pe(void *map)
{
    IMAGE_DOS_HEADER *dos_hdr;
    IMAGE_NT_HEADERS *nt_hdrs;

    dos_hdr = (IMAGE_DOS_HEADER *)map;
    if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;
    nt_hdrs = (IMAGE_NT_HEADERS *)((char *)map + dos_hdr->e_lfanew);
    return nt_hdrs->Signature == IMAGE_NT_SIGNATURE;
}

static IMAGE_IMPORT_DESCRIPTOR *get_imp_desc(void *module)
{
    IMAGE_NT_HEADERS *nt_hdrs;
    DWORD imp_desc_rva;
    nt_hdrs = GET_NT_HEADERS(module);
    if (!(imp_desc_rva = nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress))
        return NULL;
    return (IMAGE_IMPORT_DESCRIPTOR *)((char *)module + imp_desc_rva);
}

static int load_imports(void *module)
{
    IMAGE_IMPORT_DESCRIPTOR *first_imp_desc, *imp_desc;
    first_imp_desc = imp_desc = get_imp_desc(module);
    /* FIX ME: is checking Name and Stamp enough? */
    for (; imp_desc->Name || imp_desc->TimeDateStamp; ++imp_desc)
    {
        IMAGE_THUNK_DATA *name_table, *address_table, *thunk;
        char *dll_name;
        HMODULE lib_module;

        dll_name = (char *)module + imp_desc->Name;
        /* the reference count side effect is desired */
        if (!(lib_module = LoadLibraryA(dll_name)))
            goto fail;

        name_table = (IMAGE_THUNK_DATA *)((char *)module + imp_desc->OriginalFirstThunk);
        address_table = (IMAGE_THUNK_DATA *)((char *)module + imp_desc->FirstThunk);

        /* if there is no name table, use address table */
        thunk = imp_desc->OriginalFirstThunk ? name_table : address_table;
        while (thunk->u1.AddressOfData)
        {
            unsigned char *func_name;
            /* is ordinal? */
            if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                func_name = (unsigned char *)MAKE_ORDINAL(thunk->u1.Ordinal);
            else
                func_name = ((IMAGE_IMPORT_BY_NAME *)((char *)module + thunk->u1.AddressOfData))->Name;

            address_table->u1.Function = (DWORD)get_proc_address(lib_module, (char *)func_name);

            thunk++;
            address_table++;
        }
    }
    return 1;

fail:
    /* free the modules we loaded till now */
    free_imp_by_range(module, first_imp_desc, imp_desc);
    return 0;
}

/* if end is NULL, then it will continue till there are no more modules to free */
static void free_imp_by_range(void *module,
                              IMAGE_IMPORT_DESCRIPTOR *begining,
                              IMAGE_IMPORT_DESCRIPTOR *end)
{
    IMAGE_IMPORT_DESCRIPTOR *imp_desc;
    imp_desc = begining;
    for (   ;
            (imp_desc->Name || imp_desc->TimeDateStamp) && (!end || imp_desc != end);
            ++imp_desc)
    {
        char *dll_name;
        HMODULE loaded_module;

        dll_name = (char *)module + imp_desc->Name;
        if ((loaded_module = GetModuleHandleA(dll_name)))
            FreeLibrary(loaded_module);
    }
}

static void free_imports(void *module)
{
    free_imp_by_range(module, get_imp_desc(module), NULL);
}

static void fix_relocations(IMAGE_BASE_RELOCATION *base_reloc, DWORD dir_size,
                            void *new_imgbase, void *old_imgbase)
{
    IMAGE_BASE_RELOCATION *cur_reloc = base_reloc, *reloc_end;
    DWORD delta = (char *)new_imgbase - (char *)old_imgbase;

    reloc_end = (IMAGE_BASE_RELOCATION *)((char *)base_reloc + dir_size);
    /* FIX-ME: is checking virtualaddress for cur_reloc necessary? */
    while (cur_reloc < reloc_end && cur_reloc->VirtualAddress)
    {
        int count = (cur_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD *cur_entry = (WORD *)(cur_reloc + 1);
        void *page_va = (void *)((char *)new_imgbase + cur_reloc->VirtualAddress);

        while (count--)
        {
            /* is valid x86 relocation? */
            if (*cur_entry >> 12 == IMAGE_REL_BASED_HIGHLOW)
                *(DWORD *)((char *)page_va + (*cur_entry & 0x0fff)) += delta;
            cur_entry++;
        }
        /* advance to the next reloc entry */
        cur_reloc = (IMAGE_BASE_RELOCATION *)((char *)cur_reloc + cur_reloc->SizeOfBlock);
    }
}

static void copy_headers(void *dest_pe, void *src_pe)
{
    IMAGE_NT_HEADERS *nt_hdrs;
    nt_hdrs = GET_NT_HEADERS(src_pe);
    memcpy(dest_pe, src_pe, nt_hdrs->OptionalHeader.SizeOfHeaders);
}

static void copy_sections(void *dest_pe, void *src_pe)
{
    WORD i;
    IMAGE_NT_HEADERS *nt_hdrs;
    IMAGE_SECTION_HEADER *sec_hdr;

    nt_hdrs = GET_NT_HEADERS(src_pe);
    sec_hdr = IMAGE_FIRST_SECTION(nt_hdrs);
    for (i = 0; i < nt_hdrs->FileHeader.NumberOfSections; ++i, ++sec_hdr)
    {
        void *sec_dest;
        size_t padding_size;

        sec_dest = (void *)((char *)dest_pe + sec_hdr->VirtualAddress);
        /* copy the raw data from the mapped module */
        memcpy(sec_dest,
               (void *)((char *)src_pe + sec_hdr->PointerToRawData),
               sec_hdr->SizeOfRawData);
        /* set the remaining part of the section with zeros */
        padding_size = ROUND(sec_hdr->Misc.VirtualSize, nt_hdrs->OptionalHeader.SectionAlignment) - sec_hdr->SizeOfRawData;
        memset((void *)((char *)sec_dest + sec_hdr->SizeOfRawData), 0, padding_size);
    }
}

/* executable, readable, writable */
static DWORD secp2vmemp[2][2][2] =
{
    {
        /* not executable */
        {PAGE_NOACCESS, PAGE_WRITECOPY},
        {PAGE_READONLY, PAGE_READWRITE}
    },
    {
        /* executable */
        {PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY},
        {PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE}
    }
};

static DWORD secp_to_vmemp(DWORD secp)
{
    DWORD vmemp;
    int executable, readable, writable;

    executable = (secp & IMAGE_SCN_MEM_EXECUTE) != 0;
    readable = (secp & IMAGE_SCN_MEM_READ) != 0;
    writable = (secp & IMAGE_SCN_MEM_WRITE) != 0;
    vmemp = secp2vmemp[executable][readable][writable];
    if (secp & IMAGE_SCN_MEM_NOT_CACHED)
        vmemp |= PAGE_NOCACHE;
    return vmemp;
}

static void protect_module_pages(void *module)
{
    IMAGE_NT_HEADERS *nt_hdrs;
    IMAGE_SECTION_HEADER *sec_hdr;
    DWORD old_prot, new_prot;
    WORD i;

    nt_hdrs = GET_NT_HEADERS(module);
    /* protect the PE headers */
    VirtualProtect(module, nt_hdrs->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &old_prot);

    /* protect the image sections */
    sec_hdr = IMAGE_FIRST_SECTION(nt_hdrs);
    for (i = 0; i < nt_hdrs->FileHeader.NumberOfSections; ++i, ++sec_hdr)
    {
        void *section;
        section = (void *)((char *)module + sec_hdr->VirtualAddress);
        /* free the section if it's marked as discardable */
        if (sec_hdr->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
        {
            VirtualFree(section, sec_hdr->Misc.VirtualSize, MEM_DECOMMIT);
            continue;
        }
        new_prot = secp_to_vmemp(sec_hdr->Characteristics);
        VirtualProtect(section,
                       sec_hdr->Misc.VirtualSize,   /* pages affected in the range are changed */
                       new_prot,
                       &old_prot);
    }
}

/* loads dlls from memory
* returns the address of the loaded dll on successs, NULL on failure
*/
HMODULE mem_load_library(void *module_map)
{
    IMAGE_NT_HEADERS *nt_hdrs;
    HMODULE module;
    DWORD image_base, ep_rva;
    IMAGE_DATA_DIRECTORY *reloc_dir_entry;
    int relocate, apis_loaded;

    relocate = apis_loaded = 0;
    if (!is_pe(module_map))
        return NULL;

    nt_hdrs = (IMAGE_NT_HEADERS *)((char *)module_map + ((IMAGE_DOS_HEADER *)module_map)->e_lfanew);
    reloc_dir_entry = &nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    /* reserve memory for the module at image base if possible */
    image_base = nt_hdrs->OptionalHeader.ImageBase;
    module = VirtualAlloc((void *)(image_base), nt_hdrs->OptionalHeader.SizeOfImage,
                          MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    /* image base taken ? */
    if (!module)
    {
        relocate = 1;
        /* is module relocatable? */
        if (!reloc_dir_entry->VirtualAddress)
            return NULL;
        /* try to allocate it at an arbitrary address */
        module = VirtualAlloc(NULL, nt_hdrs->OptionalHeader.SizeOfImage,
                              MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!module)
            return NULL;
    }

    copy_headers(module, module_map);
    copy_sections(module, module_map);
    if (!load_imports(module))
        goto fail;
    apis_loaded = 1;
    /* relocate the module if it isn't loaded at it's prefered address */
    if (relocate)
    {
        IMAGE_BASE_RELOCATION *base_reloc;
        base_reloc = (IMAGE_BASE_RELOCATION *)((char *)module_map + rva_to_raw(reloc_dir_entry->VirtualAddress, nt_hdrs));
        fix_relocations(base_reloc, reloc_dir_entry->Size, module, (void *)image_base);
    }
    /* change the protection flags of the module pages */
    protect_module_pages(module);
    /* call DLLMain if it has one */
    if ((ep_rva = nt_hdrs->OptionalHeader.AddressOfEntryPoint))
    {
        DllMainFunc dll_main;
        dll_main = (DllMainFunc)((char *)module + ep_rva);
        if (!dll_main((HINSTANCE)module, DLL_PROCESS_ATTACH, NULL))
            goto fail;
    }

    return module;

fail:
    if (apis_loaded)
        free_imports(module);
    VirtualFree(module, 0, MEM_RELEASE);
    return NULL;
}

void mem_free_library(HMODULE *module)
{
    IMAGE_NT_HEADERS *nt_hdrs;

    nt_hdrs = (IMAGE_NT_HEADERS *)((char *)module + ((IMAGE_DOS_HEADER *)module)->e_lfanew);
    /* tell the module it's getting detached */
    if (nt_hdrs->OptionalHeader.AddressOfEntryPoint)
    {
        DllMainFunc dll_main;

        dll_main = (DllMainFunc)((char *)module + nt_hdrs->OptionalHeader.AddressOfEntryPoint);
        dll_main((HINSTANCE)module, DLL_PROCESS_DETACH, NULL);
    }
    free_imports(module);
    VirtualFree(module, 0, MEM_RELEASE);
}

void *get_proc_address(HMODULE module, const char *proc_name)
{
    IMAGE_NT_HEADERS *nt_hdrs;
    IMAGE_DATA_DIRECTORY *exp_entry;
    IMAGE_EXPORT_DIRECTORY *exp_dir;
    void **func_table;
    WORD *ord_table;
    char **name_table;
    void *address;


    nt_hdrs = GET_NT_HEADERS(module);
    exp_entry = (IMAGE_DATA_DIRECTORY *)(&nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    exp_dir = (IMAGE_EXPORT_DIRECTORY *)((char *)module + exp_entry->VirtualAddress);

    func_table = (void **)((char *)module + exp_dir->AddressOfFunctions);
    ord_table = (WORD *)((char *)module + exp_dir->AddressOfNameOrdinals);
    name_table = (char **)((char *)module + exp_dir->AddressOfNames);

    /* NULL is returned if nothing is found */
    address = NULL;


    /* is ordinal? */
    if (((DWORD)proc_name >> 16) == 0)
    {
        WORD ordinal = LOWORD(proc_name);
        DWORD ord_base = exp_dir->Base;
        /* is valid ordinal? */
        if (ordinal < ord_base || ordinal > ord_base + exp_dir->NumberOfFunctions)
            return NULL;

        /* taking ordinal base into consideration */
        address = (void *)((char *)module + (DWORD)func_table[ordinal - ord_base]);
    }
    else
    {
        DWORD i;

        /* import by name */
        for (i = 0; i < exp_dir->NumberOfNames; i++)
        {
            /* name table pointers are rvas */
            if (strcmp(proc_name, (char *)module + (DWORD)name_table[i]) == 0)
                address = (void *)((char *)module + (DWORD)func_table[ord_table[i]]);
        }
    }

    /* is forwarded? */
    if ((char *)address >= (char *)exp_dir &&
            (char *)address < (char *)exp_dir + exp_entry->Size)
    {
        char *dll_name, *func_name;
        HMODULE frwd_module;

        dll_name = strdup((char *)address);
        if (!dll_name)
            return NULL;
        func_name = strchr(dll_name, '.');
        *func_name++ = 0;

        if ((frwd_module = GetModuleHandleA(dll_name)))
            address = get_proc_address(frwd_module, func_name);
        else
            address = NULL;

        free(dll_name);
    }

    return address;
}
