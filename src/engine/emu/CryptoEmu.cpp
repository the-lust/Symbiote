#define WIN32_NO_STATUS
#include "CryptoEmu.h"
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <cstring>

static HMODULE GetNtdll()
{
    static HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) hNtdll = LoadLibraryW(L"ntdll.dll");
    return hNtdll;
}

CryptoEmu::CryptoEmu(Logger* logger)
    : m_logger(logger)
{
}

bool CryptoEmu::HandleNtQueryInformationToken(uint64_t* args, uint64_t* result)
{
    HANDLE tokenHandle = (HANDLE)(ULONG_PTR)args[0];
    auto infoClass = (TOKEN_INFORMATION_CLASS)args[1];
    PVOID outBuf = (PVOID)(uintptr_t)args[2];
    ULONG bufLen = (ULONG)args[3];
    PULONG retLen = (PULONG)(uintptr_t)args[4];

    typedef NTSTATUS (NTAPI* RealNtQueryInformationToken_t)(
        HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    static RealNtQueryInformationToken_t realFunc = (RealNtQueryInformationToken_t)
        GetProcAddress(GetNtdll(), "NtQueryInformationToken");

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (realFunc) {
        status = realFunc(tokenHandle, infoClass, outBuf, bufLen, retLen);
    }

    m_logger->Trace(LOG_EMU, "NtQueryInformationToken class=%d -> 0x%08X",
        (int)infoClass, status);
    *result = (uint64_t)status;
    return true;
}

bool CryptoEmu::HandleNtOpenProcessToken(uint64_t* args, uint64_t* result)
{
    HANDLE processHandle = (HANDLE)(ULONG_PTR)args[0];
    ACCESS_MASK access = (ACCESS_MASK)args[1];
    PHANDLE tokenHandle = (PHANDLE)(uintptr_t)args[2];

    typedef NTSTATUS (NTAPI* RealNtOpenProcessToken_t)(
        HANDLE, ACCESS_MASK, PHANDLE);
    static RealNtOpenProcessToken_t realFunc = (RealNtOpenProcessToken_t)
        GetProcAddress(GetNtdll(), "NtOpenProcessToken");

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (realFunc) {
        status = realFunc(processHandle, access, tokenHandle);
    }

    m_logger->Trace(LOG_EMU, "NtOpenProcessToken -> 0x%08X", status);
    *result = (uint64_t)status;
    return true;
}

bool CryptoEmu::HandleCryptGetProvParam(uint64_t*, uint64_t* result)
{
    // CryptGetProvParam is used to get CryptoAPI container name
    // This is a Win32 API, not a syscall. Intercepted via IAT patch.
    // If we get here via the emulator, we spoof the provider params.
    m_logger->Trace(LOG_EMU, "CryptGetProvParam intercepted");
    *result = 0; // success with default/safe values
    return true;
}

bool CryptoEmu::HandleNtDuplicateToken(uint64_t* args, uint64_t* result)
{
    HANDLE existingHandle = (HANDLE)(ULONG_PTR)args[0];
    ACCESS_MASK access = (ACCESS_MASK)args[1];
    PVOID attr = (PVOID)(uintptr_t)args[2];
    BOOLEAN effectiveOnly = (BOOLEAN)args[3];
    TOKEN_TYPE tokenType = (TOKEN_TYPE)args[4];
    PHANDLE newHandle = (PHANDLE)(uintptr_t)args[5];

    typedef NTSTATUS (NTAPI* RealNtDuplicateToken_t)(
        HANDLE, ACCESS_MASK, PVOID, BOOLEAN, TOKEN_TYPE, PHANDLE);
    static RealNtDuplicateToken_t realFunc = (RealNtDuplicateToken_t)
        GetProcAddress(GetNtdll(), "NtDuplicateToken");

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (realFunc) {
        status = realFunc(existingHandle, access, attr, effectiveOnly, tokenType, newHandle);
    }

    m_logger->Trace(LOG_EMU, "NtDuplicateToken -> 0x%08X", status);
    *result = (uint64_t)status;
    return true;
}