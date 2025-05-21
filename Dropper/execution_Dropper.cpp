/*
Replace your DLLName
*/

#include <windows.h>
#include <iostream>

typedef BOOL (*SendHttpRequestFunc)();

int main()
{
    // Load the DLL
    HMODULE hDll = LoadLibrary(L"YourDllName.dll"); // Replace with your DLL name
    if (!hDll)
    {
        std::cerr << "Failed to load DLL: " << GetLastError() << std::endl;
        return 1;
    }

    // Get the function pointer
    SendHttpRequestFunc pSendHttpRequest = (SendHttpRequestFunc)GetProcAddress(hDll, "SendHttpRequest");
    if (!pSendHttpRequest)
    {
        std::cerr << "Failed to find SendHttpRequest function: " << GetLastError() << std::endl;
        FreeLibrary(hDll);
        return 1;
    }

    // Call the function
    BOOL result = pSendHttpRequest();
    if (result)
    {
        std::cout << "HTTP request sent successfully!" << std::endl;
    }
    else
    {
        std::cerr << "Failed to send HTTP request." << std::endl;
    }

    // Clean up
    FreeLibrary(hDll);
    return result ? 0 : 1;
}
