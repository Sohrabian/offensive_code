// test.cpp
#include <windows.h>

typedef BOOL(*SendHttpRequestFunc)();

int main()
{
    HMODULE hDll = LoadLibrary(L"InternetConnection_DLL.dll");
    if (hDll)
    {
        SendHttpRequestFunc func = (SendHttpRequestFunc)GetProcAddress(hDll, "SendHttpRequest");
        if (func) func();
        FreeLibrary(hDll);
    }
    return 0;
}
