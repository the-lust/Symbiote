#pragma once
#include <windows.h>
#include <vector>
#include <cstdint>
#include "Logger.h"
#include "proxy/InlineHook.h"

class CaptureLogger;

class AllocTracker {
public:
    explicit AllocTracker(Logger* logger);
    ~AllocTracker();

    bool Initialize();
    void Shutdown();
    void SetCaptureLogger(CaptureLogger* cap) { m_capLogger = cap; }

    LONG OnException(EXCEPTION_POINTERS* ep);

private:
    struct TrackedPage {
        uint64_t baseAddr;
        uint64_t pageEnd;
        uint32_t guardHits;
        bool hasCpuid;
        bool isClean;
        bool modified;       // set on alloc/protect, cleared on rescan
        bool wasExecutable;  // previous protection state for re-encrypt detection
        bool allocAsRW;      // was originally allocated as RW (re-encrypt candidate)
        uint32_t reencryptCycle; // re-encrypt cycle counter
    };

    static const int GUARD_HIT_LIMIT = 30;
    static const int TIMER_INTERVAL_MS = 50;

    Logger* m_logger;
    CaptureLogger* m_capLogger;
    CRITICAL_SECTION m_cs;
    std::vector<TrackedPage> m_trackedPages;
    void* m_vehHandle;
    HANDLE m_timerStopEvent;
    HANDLE m_timerThread;
    bool m_initialized;

    InlineHook m_ntAllocHook;
    InlineHook m_ntProtHook;
    InlineHook m_ntFreeHook;
    InlineHook m_ntMapViewHook;
    void* m_ntAllocTrampoline;
    void* m_ntProtTrampoline;
    void* m_ntFreeTrampoline;
    void* m_ntMapViewTrampoline;

    typedef NTSTATUS(NTAPI* NtAllocateVirtualMemoryFunc)(
        HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    typedef NTSTATUS(NTAPI* NtProtectVirtualMemoryFunc)(
        HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    typedef NTSTATUS(NTAPI* NtFreeVirtualMemoryFunc)(
        HANDLE, PVOID*, PSIZE_T, ULONG);
    typedef NTSTATUS(NTAPI* NtMapViewOfSectionFunc)(
        HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER,
        PSIZE_T, DWORD, ULONG, ULONG);

    static NTSTATUS NTAPI HookedNtAllocateVirtualMemory(
        HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    static NTSTATUS NTAPI HookedNtProtectVirtualMemory(
        HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    static NTSTATUS NTAPI HookedNtFreeVirtualMemory(
        HANDLE, PVOID*, PSIZE_T, ULONG);
    static NTSTATUS NTAPI HookedNtMapViewOfSection(
        HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER,
        PSIZE_T, DWORD, ULONG, ULONG);

    static DWORD WINAPI TimerThreadProc(LPVOID param);

    void OnAllocation(void* baseAddr, SIZE_T size, ULONG protect);
    void OnProtect(void* baseAddr, SIZE_T size, ULONG newProtect);
    void OnFree(void* baseAddr);
    void OnMapView(void* baseAddr, SIZE_T size, ULONG protect);
    void ApplyGuardToPage(void* pageAddr);
    bool IsExecutable(ULONG protect);
    TrackedPage* FindPage(uint64_t addr);
    LONG HandleGuardPage(EXCEPTION_POINTERS* ep);
    void RescanTrackedPages();
};

extern AllocTracker* g_allocTracker;
