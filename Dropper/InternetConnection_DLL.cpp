/*
Visual Studio Project Setup
1. Create New Project
    File → New → Project
    Select "Windows Desktop Wizard"
    Name: "InternetConnect"
    Choose "Dynamic Link Library (DLL)"
2. Project Configuration
    Right-click project → Properties
    Set Configuration to "All Configurations"
    C/C++ → General:
        Set "Warning Level" to "Level3 (/W3)"
        Set "SDL checks" to "No (/sdl-)"
    C/C++ → Precompiled Headers:
        Set to "Not Using Precompiled Headers"
    Linker → Input → Additional Dependencies:
        Add "wininet.lib"

    rundll32 YourDllName.dll,SendHttpRequest
*/
#include <windows.h>
#include <wininet.h>
#include <iostream>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) BOOL SendHttpRequest()
{
    HINTERNET hInternet = InternetOpen(
        L"MyUserAgent/1.0",
        INTERNET_OPEN_TYPE_DIRECT,
        NULL,
        NULL,
        0
    );

    if (!hInternet)
    {
        std::cerr << "InternetOpen failed: " << GetLastError() << std::endl;
        return FALSE;
    }

    HINTERNET hConnect = InternetOpenUrl(
        hInternet,
        L"http://194.48.198.250:2121/api",  // Change to your target URL
        NULL,
        0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE,
        0
    );

    if (!hConnect)
    {
        std::cerr << "InternetOpenUrl failed: " << GetLastError() << std::endl;
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    // Read response (optional)
    char buffer[1024];
    DWORD bytesRead;
    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0)
    {
        // Process response data here
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return TRUE;
}
