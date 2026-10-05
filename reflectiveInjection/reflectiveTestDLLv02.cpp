/*
Get-Content C:\Temp\dllmain_entered.txt
Get-Content C:\Temp\reflective_payload_ran.txt
Get-Process -Id 6132 | Select-Object Id, ProcessName, StartTime
tasklist /m /fi "imagename eq cmd.exe"
or
tasklist /m /fi "imagename eq cmd.exe" /fo list

.\dumpbin.exe /dependents C:\Users\apk\source\repos\test\x64\Release\test.dll
*/

// dllmain.cpp
#include "pch.h"
#include <windows.h>
#include <cstring>

static void WriteMarker(const char* path, const char* text)
{
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w = 0;
        WriteFile(h, text, (DWORD)strlen(text), &w, NULL);
        CloseHandle(h);
    }
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        WriteMarker("C:\\Temp\\dllmain_entered.txt",
            "DllMain entered.\r\n");

        // Park forever. The thread never returns to the CRT
        // thread-teardown path, so cmd.exe stays alive.
        for (;;) {
            Sleep(60000);
        }
    }
    return TRUE;
}
