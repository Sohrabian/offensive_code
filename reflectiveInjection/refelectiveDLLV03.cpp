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

        // 1. Marker that DllMain ran
        WriteMarker("C:\\Temp\\dllmain_entered.txt",
            "DllMain entered with DLL_PROCESS_ATTACH.\r\n");

        // 2. Marker that the payload ran
        WriteMarker("C:\\Temp\\reflective_payload_ran.txt",
            "Payload executed synchronously inside DllMain.\r\n");

        // 3. Audible proof — Beep is from kernel32.dll, no GUI needed,
        //    no desktop association required, safe from reflective thread.
        Beep(1000, 300);   // 1000 Hz for 300 ms
        Beep(1500, 300);   // second tone to make it distinct
        Beep(2000, 500);   // third tone, longer

        // 4. Park forever. The thread never returns to the CRT
        //    thread-teardown path, so cmd.exe stays alive.
        for (;;) {
            Sleep(60000);
        }
    }
    return TRUE;
}
