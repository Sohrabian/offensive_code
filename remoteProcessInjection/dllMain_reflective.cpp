#include <windows.h>

// The DLL entry point
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID p) {
    return TRUE;
}

// extern "C" prevents C++ name mangling so the export is
// literally "MyDllMain" (which is what refdll.exe looks for).
extern "C" __declspec(dllexport) void MyDllMain(void) {
    MessageBoxA(NULL,
        "Reflective DLL loaded successfully!",
        "PoC",
        MB_OK | MB_ICONINFORMATION);
}
