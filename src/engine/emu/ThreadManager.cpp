#define WIN32_NO_STATUS
#include "ThreadManager.h"
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winternl.h>
#include <cstring>

typedef enum _EVENT_TYPE {
    NotificationEvent,
    SynchronizationEvent
} EVENT_TYPE;

static HMODULE GetNtdll()
{
    static HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) hNtdll = LoadLibraryW(L"ntdll.dll");
    return hNtdll;
}

ThreadManager::ThreadManager(Logger* logger)
    : m_logger(logger)
{
}

bool ThreadManager::HandleNtCreateThread(uint64_t* args, uint64_t* result)
{
    HANDLE hProcess = (HANDLE)(ULONG_PTR)args[3];
    PVOID startAddr = (PVOID)(uintptr_t)args[5];
    PVOID param = (PVOID)(uintptr_t)args[6];

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)startAddr, param, 0, NULL);

    if (hThread) {
        if (args[0]) *(HANDLE*)(uintptr_t)args[0] = hThread;
        *result = (uint64_t)STATUS_SUCCESS;
    } else {
        *result = (uint64_t)STATUS_ACCESS_DENIED;
    }

    m_logger->Trace(LOG_EMU, "NtCreateThread -> hThread=0x%p", hThread);
    return true;
}

bool ThreadManager::HandleNtOpenThread(uint64_t* args, uint64_t* result)
{
    PHANDLE threadHandle = (PHANDLE)(uintptr_t)args[0];
    ACCESS_MASK access = (ACCESS_MASK)args[1];
    PVOID attr = (PVOID)(uintptr_t)args[2];
    HANDLE clientId = (HANDLE)(ULONG_PTR)args[3];

    typedef NTSTATUS (NTAPI* RealNtOpenThread_t)(
        PHANDLE, ACCESS_MASK, PVOID, HANDLE);
    static RealNtOpenThread_t realFunc = (RealNtOpenThread_t)
        GetProcAddress(GetNtdll(), "NtOpenThread");

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (realFunc) {
        status = realFunc(threadHandle, access, attr, clientId);
    }

    *result = (uint64_t)status;
    return true;
}

bool ThreadManager::HandleNtSuspendThread(uint64_t* args, uint64_t* result)
{
    HANDLE hThread = (HANDLE)(ULONG_PTR)args[0];

    typedef NTSTATUS (NTAPI* RealNtSuspendThread_t)(HANDLE, PULONG);
    static RealNtSuspendThread_t realFunc = (RealNtSuspendThread_t)
        GetProcAddress(GetNtdll(), "NtSuspendThread");

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (realFunc) {
        status = realFunc(hThread, nullptr);
    } else {
        DWORD prev = SuspendThread(hThread);
        status = (prev != (DWORD)-1) ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
    }

    *result = (uint64_t)status;
    m_logger->Trace(LOG_EMU, "NtSuspendThread -> 0x%08X", status);
    return true;
}

bool ThreadManager::HandleNtResumeThread(uint64_t* args, uint64_t* result)
{
    HANDLE hThread = (HANDLE)(ULONG_PTR)args[0];

    typedef NTSTATUS (NTAPI* RealNtResumeThread_t)(HANDLE, PULONG);
    static RealNtResumeThread_t realFunc = (RealNtResumeThread_t)
        GetProcAddress(GetNtdll(), "NtResumeThread");

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (realFunc) {
        status = realFunc(hThread, nullptr);
    } else {
        DWORD prev = ResumeThread(hThread);
        status = (prev != (DWORD)-1) ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
    }

    *result = (uint64_t)status;
    m_logger->Trace(LOG_EMU, "NtResumeThread -> 0x%08X", status);
    return true;
}

bool ThreadManager::HandleNtTerminateThread(uint64_t* args, uint64_t* result)
{
    HANDLE hThread = (HANDLE)(ULONG_PTR)args[0];
    NTSTATUS exitCode = (NTSTATUS)args[1];

    typedef NTSTATUS (NTAPI* RealNtTerminateThread_t)(HANDLE, NTSTATUS);
    static RealNtTerminateThread_t realFunc = (RealNtTerminateThread_t)
        GetProcAddress(GetNtdll(), "NtTerminateThread");

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (realFunc) {
        status = realFunc(hThread, exitCode);
    } else {
        BOOL ok = TerminateThread(hThread, (DWORD)exitCode);
        status = ok ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
    }

    *result = (uint64_t)status;
    m_logger->Trace(LOG_EMU, "NtTerminateThread -> 0x%08X", status);
    return true;
}

bool ThreadManager::HandleNtGetContextThread(uint64_t* args, uint64_t* result)
{
    HANDLE hThread = (HANDLE)(ULONG_PTR)args[0];
    PVOID ctx = (PVOID)(uintptr_t)args[1];

    BOOL ok = GetThreadContext(hThread, (LPCONTEXT)ctx);
    if (ok && ctx) {
        CONTEXT* pCtx = (CONTEXT*)ctx;
        // Zero hardware breakpoints (HWBP countermeasure)
        if (pCtx->ContextFlags & CONTEXT_DEBUG_REGISTERS) {
            pCtx->Dr0 = 0;
            pCtx->Dr1 = 0;
            pCtx->Dr2 = 0;
            pCtx->Dr3 = 0;
            pCtx->Dr6 = 0;
            pCtx->Dr7 = 0;
        }
    }
    *result = ok ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
    return true;
}

bool ThreadManager::HandleNtSetContextThread(uint64_t* args, uint64_t* result)
{
    HANDLE hThread = (HANDLE)(ULONG_PTR)args[0];
    PVOID ctx = (PVOID)(uintptr_t)args[1];

    if (ctx) {
        CONTEXT* pCtx = (CONTEXT*)ctx;
        // Block setting hardware breakpoints (HWBP countermeasure)
        if (pCtx->ContextFlags & CONTEXT_DEBUG_REGISTERS) {
            pCtx->Dr0 = 0;
            pCtx->Dr1 = 0;
            pCtx->Dr2 = 0;
            pCtx->Dr3 = 0;
            pCtx->Dr6 = 0;
            pCtx->Dr7 = 0;
        }
    }

    BOOL ok = SetThreadContext(hThread, (LPCONTEXT)ctx);
    *result = ok ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
    return true;
}

bool ThreadManager::HandleNtQueryInformationProcess(uint64_t* args, uint64_t* result)
{
    HANDLE hProcess = (HANDLE)(ULONG_PTR)args[0];
    auto infoClass = (PROCESS_INFORMATION_CLASS)args[1];
    PVOID outBuf = (PVOID)(uintptr_t)args[2];
    ULONG bufLen = (ULONG)args[3];
    PULONG retLen = (PULONG)(uintptr_t)args[4];

    // Handle debug-related query classes
    if (infoClass == (PROCESS_INFORMATION_CLASS)7 && outBuf && bufLen >= 4) {
        // ProcessDebugPort — return 0 (not being debugged)
        *(DWORD*)outBuf = 0;
        if (retLen) *retLen = 4;
        *result = (uint64_t)STATUS_SUCCESS;
        return true;
    }

    if (infoClass == (PROCESS_INFORMATION_CLASS)0x1E && outBuf && bufLen >= sizeof(HANDLE)) {
        // ProcessDebugObjectHandle — return NULL
        *(HANDLE*)outBuf = nullptr;
        if (retLen) *retLen = sizeof(HANDLE);
        *result = (uint64_t)STATUS_SUCCESS;
        return true;
    }

    if (infoClass == (PROCESS_INFORMATION_CLASS)0x1F && outBuf && bufLen >= 4) {
        // ProcessDebugFlags — return 1 (not being debugged)
        *(DWORD*)outBuf = 1;
        if (retLen) *retLen = 4;
        *result = (uint64_t)STATUS_SUCCESS;
        return true;
    }

    // Fall through to NTDLL for other classes
    typedef NTSTATUS (NTAPI* RealNtQueryInformationProcess_t)(
        HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    static RealNtQueryInformationProcess_t realFunc = (RealNtQueryInformationProcess_t)
        GetProcAddress(GetNtdll(), "NtQueryInformationProcess");

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (realFunc) {
        status = realFunc(hProcess, infoClass, outBuf, bufLen, retLen);
    }

    *result = (uint64_t)status;
    return true;
}

bool ThreadManager::HandleNtQueryInformationThread(uint64_t* args, uint64_t* result)
{
    HANDLE hThread = (HANDLE)(ULONG_PTR)args[0];
    auto infoClass = (THREAD_INFORMATION_CLASS)args[1];
    PVOID outBuf = (PVOID)(uintptr_t)args[2];
    ULONG bufLen = (ULONG)args[3];
    PULONG retLen = (PULONG)(uintptr_t)args[4];

    typedef NTSTATUS (NTAPI* RealNtQueryInformationThread_t)(
        HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    static RealNtQueryInformationThread_t realFunc = (RealNtQueryInformationThread_t)
        GetProcAddress(GetNtdll(), "NtQueryInformationThread");

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (realFunc) {
        status = realFunc(hThread, infoClass, outBuf, bufLen, retLen);
    }

    *result = (uint64_t)status;
    return true;
}

bool ThreadManager::HandleNtCreateEvent(uint64_t* args, uint64_t* result)
{
    PHANDLE eventHandle = (PHANDLE)(uintptr_t)args[0];
    ACCESS_MASK access = (ACCESS_MASK)args[1];
    PVOID attr = (PVOID)(uintptr_t)args[2];
    EVENT_TYPE eventType = (EVENT_TYPE)args[3];
    BOOLEAN initialState = (BOOLEAN)args[4];

    typedef NTSTATUS (NTAPI* RealNtCreateEvent_t)(
        PHANDLE, ACCESS_MASK, PVOID, EVENT_TYPE, BOOLEAN);
    static RealNtCreateEvent_t realFunc = (RealNtCreateEvent_t)
        GetProcAddress(GetNtdll(), "NtCreateEvent");

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (realFunc) {
        status = realFunc(eventHandle, access, attr, eventType, initialState);
    }

    *result = (uint64_t)status;
    m_logger->Trace(LOG_EMU, "NtCreateEvent -> 0x%08X handle=0x%p", status,
        eventHandle ? *eventHandle : nullptr);
    return true;
}

bool ThreadManager::HandleNtSetEvent(uint64_t* args, uint64_t* result)
{
    HANDLE hEvent = (HANDLE)(ULONG_PTR)args[0];

    typedef NTSTATUS (NTAPI* RealNtSetEvent_t)(HANDLE, PLONG);
    static RealNtSetEvent_t realFunc = (RealNtSetEvent_t)
        GetProcAddress(GetNtdll(), "NtSetEvent");

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (realFunc) {
        LONG prevState;
        status = realFunc(hEvent, &prevState);
    }

    *result = (uint64_t)status;
    return true;
}

bool ThreadManager::HandleNtWaitForSingleObject(uint64_t* args, uint64_t* result)
{
    HANDLE hObject = (HANDLE)(ULONG_PTR)args[0];
    BOOLEAN alertable = (BOOLEAN)args[1];
    PLARGE_INTEGER timeout = (PLARGE_INTEGER)(uintptr_t)args[2];

    DWORD waitResult = WaitForSingleObjectEx(hObject,
        timeout ? (DWORD)(timeout->QuadPart / -10000) : INFINITE, alertable);

    NTSTATUS status;
    switch (waitResult) {
        case WAIT_OBJECT_0:  status = STATUS_SUCCESS; break;
        case WAIT_TIMEOUT:   status = STATUS_TIMEOUT; break;
        case WAIT_ABANDONED: status = STATUS_ABANDONED; break;
        default:             status = STATUS_ACCESS_DENIED; break;
    }

    *result = (uint64_t)status;
    m_logger->Trace(LOG_EMU, "NtWaitForSingleObject handle=0x%p -> 0x%08X", hObject, status);
    return true;
}

bool ThreadManager::HandleNtWaitForMultipleObjects(uint64_t* args, uint64_t* result)
{
    ULONG count = (ULONG)args[0];
    PVOID handles = (PVOID)(uintptr_t)args[1];
    BOOLEAN alertable = (BOOLEAN)args[3];
    PLARGE_INTEGER timeout = (PLARGE_INTEGER)(uintptr_t)args[4];

    DWORD waitResult = WaitForMultipleObjectsEx(count, (HANDLE*)handles, FALSE,
        timeout ? (DWORD)(timeout->QuadPart / -10000) : INFINITE, alertable);

    NTSTATUS status;
    switch (waitResult) {
        case WAIT_OBJECT_0:  status = STATUS_SUCCESS; break;
        case WAIT_TIMEOUT:   status = STATUS_TIMEOUT; break;
        case WAIT_ABANDONED: status = STATUS_ABANDONED; break;
        default:             status = STATUS_ACCESS_DENIED; break;
    }

    *result = (uint64_t)status;
    return true;
}

bool ThreadManager::HandleNtSignalAndWaitForSingleObject(uint64_t* args, uint64_t* result)
{
    HANDLE signalObject = (HANDLE)(ULONG_PTR)args[0];
    HANDLE waitObject = (HANDLE)(ULONG_PTR)args[1];
    BOOLEAN alertable = (BOOLEAN)args[2];
    PLARGE_INTEGER timeout = (PLARGE_INTEGER)(uintptr_t)args[3];

    typedef NTSTATUS (NTAPI* RealNtSignalAndWaitForSingleObject_t)(
        HANDLE, HANDLE, BOOLEAN, PLARGE_INTEGER);
    static RealNtSignalAndWaitForSingleObject_t realFunc = (RealNtSignalAndWaitForSingleObject_t)
        GetProcAddress(GetNtdll(), "NtSignalAndWaitForSingleObject");

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (realFunc) {
        status = realFunc(signalObject, waitObject, alertable, timeout);
    }

    *result = (uint64_t)status;
    return true;
}