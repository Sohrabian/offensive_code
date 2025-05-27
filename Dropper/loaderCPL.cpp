#include <windows.h>
#include <tchar.h>
#include <iostream>

// Manually define CPL constants if cpl.h isn't available
#define CPL_INIT        1
#define CPL_GETCOUNT    2
#define CPL_INQUIRE     3
#define CPL_SELECT      4
#define CPL_DBLCLK      5
#define CPL_STOP        6
#define CPL_EXIT        7
#define CPL_NEWINQUIRE  8
#define CPL_STARTWPARMS 9
#define CPL_SETUP       10

typedef struct {
    int idIcon;
    int idName;
    int idInfo;
    LONG_PTR lData;
} CPLINFO;

typedef struct {
    DWORD dwSize;
    DWORD dwFlags;
    DWORD dwHelpContext;
    LONG_PTR lData;
    HICON hIcon;
    TCHAR szName[32];
    TCHAR szInfo[64];
    TCHAR szHelpFile[128];
} NEWCPLINFO;

bool ExecuteCPL(const wchar_t* cplPath)
{
    // Method 1: Using control.exe (standard way)
    SHELLEXECUTEINFO sei = { sizeof(sei) };
    sei.lpVerb = L"open";
    sei.lpFile = L"control.exe";
    sei.lpParameters = cplPath;
    sei.nShow = SW_SHOWNORMAL;

    if (ShellExecuteEx(&sei))
    {
        return true;
    }

    // Method 2: Using LoadLibrary and calling CPlApplet directly
    HMODULE hCPL = LoadLibrary(cplPath);
    if (!hCPL)
    {
        std::wcerr << L"Failed to load CPL file: " << GetLastError() << std::endl;
        return false;
    }

    // Get the CPlApplet function
    typedef LONG(CALLBACK* CPAPPLET)(HWND, UINT, LPARAM, LPARAM);
    CPAPPLET CPlApplet = (CPAPPLET)GetProcAddress(hCPL, "CPlApplet");
    if (!CPlApplet)
    {
        std::wcerr << L"Failed to find CPlApplet function" << std::endl;
        FreeLibrary(hCPL);
        return false;
    }

    // Initialize the applet
    if (!CPlApplet(NULL, CPL_INIT, 0, 0))
    {
        std::wcerr << L"CPL initialization failed" << std::endl;
        FreeLibrary(hCPL);
        return false;
    }

    // Simulate double-click by sending CPL_DBLCLK message
    LONG result = CPlApplet(NULL, CPL_DBLCLK, 0, 0);

    // Clean up
    CPlApplet(NULL, CPL_EXIT, 0, 0);
    FreeLibrary(hCPL);

    return result == TRUE;
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 2)
    {
        std::wcout << L"Usage: " << argv[0] << L" <path_to_cpl_file>" << std::endl;
        return 1;
    }

    std::wcout << L"Loading CPL file: " << argv[1] << std::endl;

    if (ExecuteCPL(argv[1]))
    {
        std::wcout << L"CPL executed successfully" << std::endl;
        return 0;
    }
    else
    {
        std::wcerr << L"Failed to execute CPL" << std::endl;
        return 1;
    }
}
