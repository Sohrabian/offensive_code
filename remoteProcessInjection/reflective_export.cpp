#include <iostream>
#include <windows.h>
#include <cstring>

// =====================================================
// PE structures not always exposed by <windows.h>
// =====================================================
typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type   : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

// DllMain signature + pointer to the exported function we want to call
using DLLEntry = BOOL(WINAPI*)(HINSTANCE dll, DWORD reason, LPVOID reserved);
typedef void (*MyDllMain)();

int main()
{
    // =====================================================
    // 1. Load the DLL file from disk into memory
    // =====================================================
    HANDLE dll = CreateFileA(
        "C:\\Temp\\test.dll",
        GENERIC_READ,
        NULL,
        NULL,
        OPEN_EXISTING,
        NULL,
        NULL);

    if (dll == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] CreateFileA failed. Error: " << GetLastError() << "\n";
        std::cerr << "[!] Make sure test.dll exists at C:\\Temp\\test.dll\n";
        return 1;
    }

    DWORD64 dllSize = GetFileSize(dll, NULL);
    if (dllSize == INVALID_FILE_SIZE || dllSize == 0) {
        std::cerr << "[!] GetFileSize failed. Error: " << GetLastError() << "\n";
        CloseHandle(dll);
        return 1;
    }

    LPVOID dllBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dllSize);
    if (!dllBytes) {
        std::cerr << "[!] HeapAlloc failed. Error: " << GetLastError() << "\n";
        CloseHandle(dll);
        return 1;
    }

    DWORD outSize = 0;
    if (!ReadFile(dll, dllBytes, (DWORD)dllSize, &outSize, NULL)) {
        std::cerr << "[!] ReadFile failed. Error: " << GetLastError() << "\n";
        HeapFree(GetProcessHeap(), 0, dllBytes);
        CloseHandle(dll);
        return 1;
    }

    // =====================================================
    // 2. Parse the in-memory DLL headers
    // =====================================================
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)dllBytes;
    if (dosHeaders->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "[!] Not a valid PE file (MZ signature missing)\n";
        HeapFree(GetProcessHeap(), 0, dllBytes);
        CloseHandle(dll);
        return 1;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)
        ((DWORD_PTR)dllBytes + dosHeaders->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "[!] Not a valid PE file (NT signature missing)\n";
        HeapFree(GetProcessHeap(), 0, dllBytes);
        CloseHandle(dll);
        return 1;
    }

    SIZE_T dllImageSize = ntHeaders->OptionalHeader.SizeOfImage;
    std::cout << "[*] DLL loaded: " << dllSize << " bytes, image size: "
              << dllImageSize << " bytes\n";

    // =====================================================
    // 3. Allocate memory for the mapped image
    // =====================================================
    LPVOID dllBase = VirtualAlloc(
        (LPVOID)ntHeaders->OptionalHeader.ImageBase,
        dllImageSize,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);

    if (!dllBase) {
        std::cout << "[*] Preferred base unavailable, allocating elsewhere\n";
        dllBase = VirtualAlloc(
            NULL,
            dllImageSize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE);
    }

    if (!dllBase) {
        std::cerr << "[!] VirtualAlloc failed. Error: " << GetLastError() << "\n";
        HeapFree(GetProcessHeap(), 0, dllBytes);
        CloseHandle(dll);
        return 1;
    }
    std::cout << "[*] Mapped image at: 0x"
              << std::hex << (DWORD_PTR)dllBase << std::dec << "\n";

    // =====================================================
    // 4. Compute relocation delta
    // =====================================================
    DWORD_PTR deltaImageBase = (DWORD_PTR)dllBase -
                               (DWORD_PTR)ntHeaders->OptionalHeader.ImageBase;

    // =====================================================
    // 5. Copy DLL headers into the mapped image
    // =====================================================
    std::memcpy(dllBase, dllBytes, ntHeaders->OptionalHeader.SizeOfHeaders);

    // =====================================================
    // 6. Copy each section into the mapped image
    // =====================================================
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (size_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        LPVOID sectionDestination = (LPVOID)(
            (DWORD_PTR)dllBase + (DWORD_PTR)section->VirtualAddress);

        LPVOID sectionBytes = (LPVOID)(
            (DWORD_PTR)dllBytes + (DWORD_PTR)section->PointerToRawData);

        std::memcpy(sectionDestination, sectionBytes, section->SizeOfRawData);
        section++;
    }
    std::cout << "[*] Sections copied\n";

    // =====================================================
    // 7. Apply base relocations
    // =====================================================
    IMAGE_DATA_DIRECTORY relocations =
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (relocations.Size > 0) {
        DWORD_PTR relocationTable = relocations.VirtualAddress + (DWORD_PTR)dllBase;
        DWORD     relocationsProcessed = 0;

        while (relocationsProcessed < relocations.Size) {
            PBASE_RELOCATION_BLOCK relocBlock =
                (PBASE_RELOCATION_BLOCK)(relocationTable + relocationsProcessed);
            relocationsProcessed += sizeof(BASE_RELOCATION_BLOCK);

            DWORD relocCount =
                (relocBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) /
                sizeof(BASE_RELOCATION_ENTRY);

            PBASE_RELOCATION_ENTRY relocEntries =
                (PBASE_RELOCATION_ENTRY)(relocationTable + relocationsProcessed);

            for (DWORD i = 0; i < relocCount; i++) {
                relocationsProcessed += sizeof(BASE_RELOCATION_ENTRY);

                if (relocEntries[i].Type == 0)
                    continue;

                DWORD_PTR relocRVA = relocBlock->PageAddress + relocEntries[i].Offset;
                DWORD_PTR addressToPatch = 0;

                ReadProcessMemory(
                    GetCurrentProcess(),
                    (LPCVOID)((DWORD_PTR)dllBase + relocRVA),
                    &addressToPatch,
                    sizeof(DWORD_PTR),
                    NULL);

                addressToPatch += deltaImageBase;

                std::memcpy(
                    (PVOID)((DWORD_PTR)dllBase + relocRVA),
                    &addressToPatch,
                    sizeof(DWORD_PTR));
            }
        }
        std::cout << "[*] Relocations applied\n";
    }

    // =====================================================
    // 8. Resolve the Import Address Table (IAT)
    // =====================================================
    IMAGE_DATA_DIRECTORY importsDirectory =
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (importsDirectory.Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR importDescriptor =
            (PIMAGE_IMPORT_DESCRIPTOR)(
                importsDirectory.VirtualAddress + (DWORD_PTR)dllBase);

        while (importDescriptor->Name != NULL) {
            LPCSTR libraryName =
                (LPCSTR)(importDescriptor->Name + (DWORD_PTR)dllBase);
            HMODULE library = LoadLibraryA(libraryName);

            if (library) {
                PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(
                    (DWORD_PTR)dllBase + importDescriptor->FirstThunk);

                while (thunk->u1.AddressOfData != NULL) {
                    if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                        LPCSTR functionOrdinal =
                            (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
                        thunk->u1.Function =
                            (DWORD_PTR)GetProcAddress(library, functionOrdinal);
                    }
                    else {
                        PIMAGE_IMPORT_BY_NAME functionName =
                            (PIMAGE_IMPORT_BY_NAME)(
                                (DWORD_PTR)dllBase + thunk->u1.AddressOfData);
                        DWORD_PTR functionAddress =
                            (DWORD_PTR)GetProcAddress(library, functionName->Name);
                        thunk->u1.Function = functionAddress;
                    }
                    ++thunk;
                }
            }
            importDescriptor++;
        }
        std::cout << "[*] Imports resolved\n";
    }

    // =====================================================
    // 9. EXECUTE — find the exported function and call it
    // =====================================================
    IMAGE_DATA_DIRECTORY exportDirInfo =
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (exportDirInfo.Size == 0) {
        std::cerr << "[!] No export directory found\n";
        HeapFree(GetProcessHeap(), 0, dllBytes);
        CloseHandle(dll);
        return 1;
    }

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE*)dllBase + exportDirInfo.VirtualAddress);

    DWORD* nameRVAs     = (DWORD*)((BYTE*)dllBase + exportDir->AddressOfNames);
    WORD*  ordinals     = (WORD* )((BYTE*)dllBase + exportDir->AddressOfNameOrdinals);
    DWORD* functionRVAs = (DWORD*)((BYTE*)dllBase + exportDir->AddressOfFunctions);

    const char* targetName = "MyDllMain";
    MyDllMain   targetFunc = NULL;

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* funcName = (const char*)((BYTE*)dllBase + nameRVAs[i]);
        if (lstrcmpA(funcName, targetName) == 0) {
            WORD  ordinal = ordinals[i];
            DWORD funcRVA = functionRVAs[ordinal];
            targetFunc = (MyDllMain)((BYTE*)dllBase + funcRVA);
            std::cout << "[*] Found export '" << targetName
                      << "' at 0x" << std::hex
                      << (DWORD_PTR)targetFunc << std::dec << "\n";
            break;
        }
    }

    if (targetFunc) {
        std::cout << "[*] Calling " << targetName << "()...\n";
        targetFunc();
        std::cout << "[+] Function returned\n";
    } else {
        std::cerr << "[!] Export '" << targetName << "' not found in DLL\n";
        std::cerr << "[!] Run: dumpbin /exports C:\\Temp\\test.dll\n";
    }

    // =====================================================
    // 10. Cleanup
    // =====================================================
    CloseHandle(dll);
    HeapFree(GetProcessHeap(), 0, dllBytes);

    std::cout << "[+] Done\n";
    return 0;
}
