// dllmain.cpp
#include "pch.h"
#include <windows.h>
#include <cstdio>

static DWORD WINAPI PayloadThread(LPVOID)
{
    // 1. Write a marker file — this ALWAYS works if the thread runs
    HANDLE h = CreateFileA(
        "C:\\Temp\\reflective_payload_ran.txt",
        GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (h != INVALID_HANDLE_VALUE) {
        const char* msg = "Payload thread executed inside target process.\r\n";
        DWORD written = 0;
        WriteFile(h, msg, (DWORD)strlen(msg), &written, NULL);
        CloseHandle(h);
    }

    // 2. Also try MessageBox
    MessageBoxA(NULL, "Payload thread ran!", "Reflective Payload",
        MB_OK | MB_ICONINFORMATION);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        // Write a marker that DllMain itself ran
        HANDLE h = CreateFileA(
            "C:\\Temp\\dllmain_entered.txt",
            GENERIC_WRITE, 0, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            const char* msg = "DllMain entered with DLL_PROCESS_ATTACH.\r\n";
            DWORD written = 0;
            WriteFile(h, msg, (DWORD)strlen(msg), &written, NULL);
            CloseHandle(h);
        }

        HANDLE t = CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
