#define WIN32_NO_STATUS
#include "MemoryEmu.h"
#include <winternl.h>
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#include <cstring>

// MEMORY_INFORMATION_CLASS not in user-mode headers, define it ourselves
typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation = 0,
    MemoryWorkingSetInformation = 1,
    MemoryMappedFilenameInformation = 2,
    MemoryRegionInformation = 3,
    MemoryWorkingSetExInformation = 4,
    MemorySharedCommitInformation = 5,
    MemoryImageInformation = 6,
    MemoryRegionInformationEx = 7,
    MemoryPrivilegedBasicInformation = 8,
} MEMORY_INFORMATION_CLASS;

// Real fucntion pointrs loaded from ntdll
typedef NTSTATUS (NTAPI* RealNtAllocateVirtualMemory_t)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI* RealNtFreeVirtualMemory_t)(
    HANDLE, PVOID*, PSIZE_T, ULONG);
typedef NTSTATUS (NTAPI* RealNtProtectVirtualMemory_t)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI* RealNtQueryVirtualMemory_t)(
    HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);

static RealNtAllocateVirtualMemory_t RealNtAllocateVirtualMemory = nullptr;
static RealNtFreeVirtualMemory_t RealNtFreeVirtualMemory = nullptr;
static RealNtProtectVirtualMemory_t RealNtProtectVirtualMemory = nullptr;
static RealNtQueryVirtualMemory_t RealNtQueryVirtualMemory = nullptr;

static void InitRealFuncs()
{
    if (RealNtAllocateVirtualMemory) return;
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        hNtdll = LoadLibraryW(L"ntdll.dll");
    }
    if (hNtdll) {
        RealNtAllocateVirtualMemory = (decltype(RealNtAllocateVirtualMemory))
            GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
        RealNtFreeVirtualMemory = (decltype(RealNtFreeVirtualMemory))
            GetProcAddress(hNtdll, "NtFreeVirtualMemory");
        RealNtProtectVirtualMemory = (decltype(RealNtProtectVirtualMemory))
            GetProcAddress(hNtdll, "NtProtectVirtualMemory");
        RealNtQueryVirtualMemory = (decltype(RealNtQueryVirtualMemory))
            GetProcAddress(hNtdll, "NtQueryVirtualMemory");
    }
}

MemoryEmu::MemoryEmu(Logger* logger)
    : m_logger(logger), m_state(UNINITIALIZED)
{
    InitRealFuncs();
}

bool MemoryEmu::HandleNtAllocateVirtualMemory(uint64_t* args, uint64_t* result)
{
    // args[0]=ProcessHandle, [1]=Baseadress*, [2]=ZeroBits, [3]=RegionSize*,
    // [4]=AllocationType, [5]=Protect
    HANDLE hProcess = (HANDLE)(ULONG_PTR)args[0];
    PVOID baseAddr = (PVOID)(ULONG_PTR)args[1];
    ULONG_PTR zeroBits = (ULONG_PTR)args[2];
    SIZE_T regionSize = *(SIZE_T*)(uintptr_t)args[3];
    ULONG allocType = (ULONG)args[4];
    ULONG protect = (ULONG)args[5];

    NTSTATUS status;
    if (RealNtAllocateVirtualMemory) {
        status = RealNtAllocateVirtualMemory(hProcess, &baseAddr, zeroBits, &regionSize, allocType, protect);
        if (NT_SUCCESS(status)) {
            *(PVOID*)(uintptr_t)args[1] = baseAddr;
            *(SIZE_T*)(uintptr_t)args[3] = regionSize;
        }
    } else {
        PVOID addr = VirtualAllocEx(hProcess, NULL, regionSize, allocType, protect);
        if (addr) {
            *(PVOID*)(uintptr_t)args[1] = addr;
            *(SIZE_T*)(uintptr_t)args[3] = regionSize;
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_NO_MEMORY;
        }
    }

    *result = (uint64_t)status;
    m_logger->Trace(LOG_EMU, "NtAllocateVirtualMemory -> 0x%08X base=%p size=%zu", status, baseAddr, regionSize);
    return true;
}

bool MemoryEmu::HandleNtFreeVirtualMemory(uint64_t* args, uint64_t* result)
{
    // args[0]=ProcessHandle, [1]=Baseadress*, [2]=RegionSize*, [3]=FreeType
    HANDLE hProcess = (HANDLE)(ULONG_PTR)args[0];
    PVOID baseAddr = *(PVOID*)(uintptr_t)args[1];
    SIZE_T regionSize = *(SIZE_T*)(uintptr_t)args[2];
    ULONG freeType = (ULONG)args[3];

    NTSTATUS status;
    if (RealNtFreeVirtualMemory) {
        status = RealNtFreeVirtualMemory(hProcess, &baseAddr, &regionSize, freeType);
    } else {
        BOOL ok = VirtualFreeEx(hProcess, baseAddr, regionSize, freeType);
        status = ok ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    }

    *result = (uint64_t)status;
    m_logger->Trace(LOG_EMU, "NtFreeVirtualMemory -> 0x%08X", status);
    return true;
}

bool MemoryEmu::HandleNtProtectVirtualMemory(uint64_t* args, uint64_t* result)
{
    // args[0]=ProcessHandle, [1]=Baseadress*, [2]=RegionSize*, [3]=NewProtect, [4]=OldProtect*
    HANDLE hProcess = (HANDLE)(ULONG_PTR)args[0];
    PVOID baseAddr = *(PVOID*)(uintptr_t)args[1];
    SIZE_T regionSize = *(SIZE_T*)(uintptr_t)args[2];
    ULONG newProtect = (ULONG)args[3];
    ULONG oldProtect = 0;

    NTSTATUS status;
    if (RealNtProtectVirtualMemory) {
        status = RealNtProtectVirtualMemory(hProcess, &baseAddr, &regionSize, newProtect, &oldProtect);
    } else {
        BOOL ok = VirtualProtectEx(hProcess, baseAddr, regionSize, newProtect, (PDWORD)&oldProtect);
        status = ok ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    }

    m_logger->Trace(LOG_EMU, "NtProtectVirtualMemory -> 0x%08X", status);
    *result = (uint64_t)status;
    return true;
}

bool MemoryEmu::HandleNtQueryVirtualMemory(uint64_t* args, uint64_t* result)
{
    HANDLE hProcess = (HANDLE)(ULONG_PTR)args[0];
    PVOID baseAddr = (PVOID)(uintptr_t)args[1];
    auto infoClass = (MEMORY_INFORMATION_CLASS)args[2];
    PVOID outBuf = (PVOID)(uintptr_t)args[3];
    SIZE_T bufLen = (SIZE_T)args[4];
    PSIZE_T retLen = (PSIZE_T)(uintptr_t)args[5];

    NTSTATUS status;
    if (RealNtQueryVirtualMemory) {
        status = RealNtQueryVirtualMemory(hProcess, baseAddr, infoClass, outBuf, bufLen, retLen);
    } else {
        if (infoClass == MemoryBasicInformation) {
            MEMORY_BASIC_INFORMATION mbi;
            SIZE_T sz = VirtualQueryEx(hProcess, baseAddr, &mbi, sizeof(mbi));
            if (sz && outBuf && bufLen >= sizeof(MEMORY_BASIC_INFORMATION)) {
                memcpy(outBuf, &mbi, sizeof(mbi));
                if (retLen) *retLen = sizeof(mbi);
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        } else {
            status = STATUS_INVALID_INFO_CLASS;
        }
    }

    *result = (uint64_t)status;
    return true;
}