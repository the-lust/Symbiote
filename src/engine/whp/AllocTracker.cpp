#define WIN32_NO_STATUS
#include "AllocTracker.h"
#include "capture/CaptureLogger.h"
#include <windows.h>
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#pragma comment(lib, "ntdll.lib")

AllocTracker* g_allocTracker = nullptr;

AllocTracker::AllocTracker(Logger* logger)
    : m_logger(logger), m_capLogger(nullptr), m_vehHandle(nullptr), m_timerStopEvent(nullptr),
      m_timerThread(nullptr), m_initialized(false),
      m_ntAllocTrampoline(nullptr), m_ntProtTrampoline(nullptr),
      m_ntFreeTrampoline(nullptr), m_ntMapViewTrampoline(nullptr)
{
    InitializeCriticalSection(&m_cs);
}

AllocTracker::~AllocTracker()
{
    Shutdown();
    DeleteCriticalSection(&m_cs);
}

bool AllocTracker::Initialize()
{
    if (m_initialized) return true;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        m_logger->Trace(LOG_WARNING, "AllocTracker: ntdll not found");
        return false;
    }

    void* ntAllocAddr = GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    void* ntProtAddr = GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    void* ntFreeAddr = GetProcAddress(hNtdll, "NtFreeVirtualMemory");
    void* ntMapViewAddr = GetProcAddress(hNtdll, "NtMapViewOfSection");

    if (!ntAllocAddr || !ntProtAddr || !ntFreeAddr || !ntMapViewAddr) {
        m_logger->Trace(LOG_WARNING, "AllocTracker: GetProcAddress failed");
        return false;
    }

    if (!m_ntAllocHook.Install(ntAllocAddr, (void*)HookedNtAllocateVirtualMemory)) {
        m_logger->Trace(LOG_WARNING, "AllocTracker: failed to hook NtAllocateVirtualMemory");
        return false;
    }
    m_ntAllocTrampoline = m_ntAllocHook.GetTrampoline();

    if (!m_ntProtHook.Install(ntProtAddr, (void*)HookedNtProtectVirtualMemory)) {
        m_logger->Trace(LOG_WARNING, "AllocTracker: failed to hook NtProtectVirtualMemory");
        m_ntAllocHook.Remove();
        return false;
    }
    m_ntProtTrampoline = m_ntProtHook.GetTrampoline();

    if (!m_ntFreeHook.Install(ntFreeAddr, (void*)HookedNtFreeVirtualMemory)) {
        m_logger->Trace(LOG_WARNING, "AllocTracker: failed to hook NtFreeVirtualMemory");
        m_ntAllocHook.Remove();
        m_ntProtHook.Remove();
        return false;
    }
    m_ntFreeTrampoline = m_ntFreeHook.GetTrampoline();

    if (!m_ntMapViewHook.Install(ntMapViewAddr, (void*)HookedNtMapViewOfSection)) {
        m_logger->Trace(LOG_WARNING, "AllocTracker: failed to hook NtMapViewOfSection");
        m_ntAllocHook.Remove();
        m_ntProtHook.Remove();
        m_ntFreeHook.Remove();
        return false;
    }
    m_ntMapViewTrampoline = m_ntMapViewHook.GetTrampoline();

    m_logger->Trace(LOG_INFO, "AllocTracker: NtAllocateVirtualMemory hooked at %p", ntAllocAddr);
    m_logger->Trace(LOG_INFO, "AllocTracker: NtProtectVirtualMemory hooked at %p", ntProtAddr);
    m_logger->Trace(LOG_INFO, "AllocTracker: NtFreeVirtualMemory hooked at %p", ntFreeAddr);
    m_logger->Trace(LOG_INFO, "AllocTracker: NtMapViewOfSection hooked at %p", ntMapViewAddr);

    g_allocTracker = this;
    m_vehHandle = AddVectoredExceptionHandler(1, [](EXCEPTION_POINTERS* ep) -> LONG {
        return g_allocTracker ? g_allocTracker->OnException(ep) : EXCEPTION_CONTINUE_SEARCH;
    });

    m_timerStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (m_timerStopEvent) {
        m_timerThread = CreateThread(NULL, 0, TimerThreadProc, this, 0, NULL);
    }

    m_initialized = true;
    m_logger->Trace(LOG_INFO, "AllocTracker: initialized");
    return true;
}

void AllocTracker::Shutdown()
{
    if (!m_initialized) return;

    if (m_timerStopEvent) {
        SetEvent(m_timerStopEvent);
        if (m_timerThread) {
            WaitForSingleObject(m_timerThread, 1000);
            CloseHandle(m_timerThread);
            m_timerThread = nullptr;
        }
        CloseHandle(m_timerStopEvent);
        m_timerStopEvent = nullptr;
    }

    if (m_vehHandle) {
        RemoveVectoredExceptionHandler(m_vehHandle);
        m_vehHandle = nullptr;
    }

    m_ntAllocHook.Remove();
    m_ntProtHook.Remove();
    m_ntFreeHook.Remove();
    m_ntMapViewHook.Remove();
    m_initialized = false;
    g_allocTracker = nullptr;

    EnterCriticalSection(&m_cs);
    m_trackedPages.clear();
    LeaveCriticalSection(&m_cs);

    m_logger->Trace(LOG_INFO, "AllocTracker: shutdown");
}

bool AllocTracker::IsExecutable(ULONG protect)
{
    return (protect & 0xF0) >= PAGE_EXECUTE_READ;
}

void AllocTracker::OnAllocation(void* baseAddr, SIZE_T size, ULONG protect)
{
    if (!IsExecutable(protect)) return;
    if (!baseAddr) return;

    uint64_t start = (uint64_t)baseAddr;
    uint64_t end = start + size;

    // Collect pages to guard, then set guards outside CS to avoid re-entrancy
    uint64_t guardPages[64];
    int guardCount = 0;

    EnterCriticalSection(&m_cs);

    for (uint64_t page = start & ~0xFFFULL; page < end && guardCount < 64; page += 0x1000) {
        bool found = false;
        for (auto& tp : m_trackedPages) {
            if (tp.baseAddr == page) { found = true; break; }
        }
        if (found) continue;

        TrackedPage tp;
        tp.baseAddr = page;
        tp.pageEnd = page + 0x1000;
        tp.guardHits = 0;
        tp.hasCpuid = false;
        tp.isClean = false;
        tp.modified = true;
        tp.wasExecutable = false;
        tp.allocAsRW = (protect == PAGE_READWRITE);
        tp.reencryptCycle = 0;
        m_trackedPages.push_back(tp);
        guardPages[guardCount++] = page;
    }

    LeaveCriticalSection(&m_cs);

    if (m_capLogger && guardCount > 0) {
        m_capLogger->CaptureAlloc(0, baseAddr, size, protect);
    }

    for (int i = 0; i < guardCount; i++) {
        DWORD oldProtect;
        VirtualProtect((LPVOID)guardPages[i], 0x1000,
            PAGE_EXECUTE_READWRITE | PAGE_GUARD, &oldProtect);
    }
}

void AllocTracker::OnProtect(void* baseAddr, SIZE_T size, ULONG newProtect)
{
    if (!baseAddr) return;

    bool nowExecutable = IsExecutable(newProtect);
    uint64_t start = (uint64_t)baseAddr;
    uint64_t end = start + size;

    uint64_t guardPages[64];
    int guardCount = 0;

    EnterCriticalSection(&m_cs);

    for (uint64_t page = start & ~0xFFFULL; page < end; page += 0x1000) {
        bool found = false;
        for (size_t i = 0; i < m_trackedPages.size(); ) {
            if (m_trackedPages[i].baseAddr == page) {
                found = true;
                TrackedPage& tp = m_trackedPages[i];

                // Detect re-encrypt: transitioning from executable back to non-executable
                if (tp.wasExecutable && !nowExecutable) {
                    tp.reencryptCycle++;
                    tp.allocAsRW = (newProtect == PAGE_READWRITE);
                    if (m_capLogger) {
                        m_capLogger->CaptureReencrypt(0, (void*)page, tp.wasExecutable ? 0x20 : 0, newProtect);
                    }
                    m_logger->Trace(LOG_INFO,
                        "AllocTracker: re-encrypt cycle %u at %llx",
                        tp.reencryptCycle, page);
                }

                if (!nowExecutable) {
                    m_trackedPages.erase(m_trackedPages.begin() + i);
                    continue;
                }

                tp.wasExecutable = true;
                tp.modified = true;
                break;
            }
            i++;
        }

        if (!found && nowExecutable && guardCount < 64) {
            TrackedPage tp;
            tp.baseAddr = page;
            tp.pageEnd = page + 0x1000;
            tp.guardHits = 0;
            tp.hasCpuid = false;
            tp.isClean = false;
            tp.modified = true;
            tp.wasExecutable = true;
            tp.allocAsRW = false;
            tp.reencryptCycle = 0;
            m_trackedPages.push_back(tp);
            guardPages[guardCount++] = page;
        }
    }

    LeaveCriticalSection(&m_cs);

    for (int i = 0; i < guardCount; i++) {
        DWORD oldProtect;
        VirtualProtect((LPVOID)guardPages[i], 0x1000,
            PAGE_EXECUTE_READWRITE | PAGE_GUARD, &oldProtect);
    }
}

AllocTracker::TrackedPage* AllocTracker::FindPage(uint64_t addr)
{
    for (auto& tp : m_trackedPages) {
        if (addr >= tp.baseAddr && addr < tp.pageEnd)
            return &tp;
    }
    return nullptr;
}

LONG AllocTracker::OnException(EXCEPTION_POINTERS* ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_GUARD_PAGE) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    return HandleGuardPage(ep);
}

LONG AllocTracker::HandleGuardPage(EXCEPTION_POINTERS* ep)
{
    uint64_t faultAddr = ep->ExceptionRecord->ExceptionInformation[1];
    uint64_t rip = (uint64_t)ep->ContextRecord->Rip;

    // Stack-spoiling defense: save top of stack before processing, restore after.
    // Denuvo stores critical values in high unused stack space before triggering
    // exceptions; Windows' exception dispatch overwrites those values.
    uint64_t savedStackBackup[64];
    uint64_t rsp = ep->ContextRecord->Rsp;
    memcpy(savedStackBackup, (void*)rsp, sizeof(savedStackBackup));

    auto restoreStack = [&]() {
        memcpy((void*)rsp, savedStackBackup, sizeof(savedStackBackup));
    };

    EnterCriticalSection(&m_cs);

    TrackedPage* page = FindPage(faultAddr);
    if (!page) {
        LeaveCriticalSection(&m_cs);
        restoreStack();
        return EXCEPTION_CONTINUE_SEARCH;
    }

    page->guardHits++;
    uint32_t hits = page->guardHits;

    if (hits > GUARD_HIT_LIMIT) {
        page->isClean = true;
        LeaveCriticalSection(&m_cs);
        restoreStack();
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    uint64_t pageBase = page->baseAddr;

    uint8_t* code = (uint8_t*)rip;
    bool isCpuid = (code[0] == 0x0F && code[1] == 0xA2);
    bool isRdtsc = (code[0] == 0x0F && code[1] == 0x31);
    bool isRdtscp = (code[0] == 0x0F && code[1] == 0x01 && code[2] == 0xF9);

    if (isCpuid || isRdtsc || isRdtscp) {
        if (isCpuid) page->hasCpuid = true;

        LeaveCriticalSection(&m_cs);

        // Full register emulation: execute real instruction then spoof
        if (isCpuid) {
            int cpuInfo[4] = {0};
            uint32_t leaf = (uint32_t)ep->ContextRecord->Rax;
            uint32_t subleaf = (uint32_t)ep->ContextRecord->Rcx;
            __cpuidex(cpuInfo, leaf, subleaf);
            ep->ContextRecord->Rax = (uint64_t)(uint32_t)cpuInfo[0];
            ep->ContextRecord->Rbx = (uint64_t)(uint32_t)cpuInfo[1];
            ep->ContextRecord->Rcx = (uint64_t)(uint32_t)cpuInfo[2];
            ep->ContextRecord->Rdx = (uint64_t)(uint32_t)cpuInfo[3];

            // Mirror the WHP spoofing: clear hypervisor bit
            if (leaf == 1) {
                ep->ContextRecord->Rcx &= ~(1u << 31);
                ep->ContextRecord->Rcx &= ~(1u << 6);
            }
        } else if (isRdtsc) {
            ep->ContextRecord->Rax = (uint64_t)(uint32_t)__rdtsc();
            ep->ContextRecord->Rdx = (uint64_t)(__rdtsc() >> 32);
        } else if (isRdtscp) {
            unsigned aux;
            uint64_t tsc = __rdtscp(&aux);
            ep->ContextRecord->Rax = (uint64_t)(uint32_t)tsc;
            ep->ContextRecord->Rdx = (uint64_t)(tsc >> 32);
            ep->ContextRecord->Rcx = 1;
        }

        // Advance RIP past the instruction
        ep->ContextRecord->Rip += (isRdtscp ? 3 : 2);

        if (m_capLogger) {
            if (isCpuid) {
                uint32_t leaf = (uint32_t)ep->ContextRecord->Rax;
                uint32_t subleaf = (uint32_t)ep->ContextRecord->Rcx;
                m_capLogger->CaptureGuardPageCpuid(rip, leaf, subleaf,
                    (uint32_t)ep->ContextRecord->Rax,
                    (uint32_t)ep->ContextRecord->Rbx,
                    (uint32_t)ep->ContextRecord->Rcx,
                    (uint32_t)ep->ContextRecord->Rdx,
                    (void*)pageBase);
            } else if (isRdtsc) {
                m_capLogger->CaptureRdtsc("RDTSC", rip, __rdtsc());
            } else if (isRdtscp) {
                unsigned aux; m_capLogger->CaptureRdtsc("RDTSCP", rip, __rdtscp(&aux));
            }
        }

        m_logger->Trace(LOG_INFO,
            "AllocTracker: emulated %s at %p in tracked page %llx (hit %u)",
            isCpuid ? "CPUID" : isRdtsc ? "RDTSC" : "RDTSCP",
            (void*)rip, pageBase, hits);

        restoreStack();
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    LeaveCriticalSection(&m_cs);

    DWORD oldProt2;
    VirtualProtect((LPVOID)pageBase, 0x1000,
        PAGE_EXECUTE_READWRITE | PAGE_GUARD, &oldProt2);

    restoreStack();
    return EXCEPTION_CONTINUE_EXECUTION;
}

void AllocTracker::RescanTrackedPages()
{
    EnterCriticalSection(&m_cs);

    for (size_t idx = 0; idx < m_trackedPages.size(); idx++) {
        TrackedPage& page = m_trackedPages[idx];

        // Skip clean pages (not modified since last rescan)
        if (!page.modified) continue;
        page.modified = false;

        uint8_t* start = (uint8_t*)page.baseAddr;

        __try {
            for (uint32_t off = 0; off < 0x1000 - 3; off++) {
                if (start[off] == 0x0F) {
                    if (start[off + 1] == 0xA2) {
                        page.hasCpuid = true;
                        page.isClean = false;
                        off += 1;
                    } else if (start[off + 1] == 0x31) {
                        off += 1;
                    } else if (start[off + 1] == 0x01 && start[off + 2] == 0xF9) {
                        off += 2;
                    }
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            // Page was freed - skip
        }
    }

    LeaveCriticalSection(&m_cs);
}

DWORD WINAPI AllocTracker::TimerThreadProc(LPVOID param)
{
    AllocTracker* self = (AllocTracker*)param;

    while (true) {
        DWORD wait = WaitForSingleObject(self->m_timerStopEvent, TIMER_INTERVAL_MS);
        if (wait == WAIT_OBJECT_0) break;
        self->RescanTrackedPages();
    }

    return 0;
}

NTSTATUS NTAPI AllocTracker::HookedNtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
    auto orig = (NtAllocateVirtualMemoryFunc)g_allocTracker->m_ntAllocTrampoline;
    if (!orig) return STATUS_NOT_IMPLEMENTED;

    NTSTATUS status = orig(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

    if (NT_SUCCESS(status) && ProcessHandle == GetCurrentProcess() && BaseAddress && *BaseAddress) {
        g_allocTracker->OnAllocation(*BaseAddress, *RegionSize, Protect);
    }

    return status;
}

NTSTATUS NTAPI AllocTracker::HookedNtProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect)
{
    auto orig = (NtProtectVirtualMemoryFunc)g_allocTracker->m_ntProtTrampoline;
    if (!orig) return STATUS_NOT_IMPLEMENTED;

    ULONG oldProtLocal = 0;
    NTSTATUS status = orig(ProcessHandle, BaseAddress, RegionSize, NewProtect, &oldProtLocal);

    if (NT_SUCCESS(status) && ProcessHandle == GetCurrentProcess() && BaseAddress && *BaseAddress) {
        g_allocTracker->OnProtect(*BaseAddress, *RegionSize, NewProtect);
    }

    if (OldProtect) *OldProtect = oldProtLocal;
    return status;
}

void AllocTracker::OnFree(void* baseAddr)
{
    if (!baseAddr) return;
    uint64_t addr = (uint64_t)baseAddr;

    EnterCriticalSection(&m_cs);

    for (size_t i = 0; i < m_trackedPages.size(); ) {
        if (m_trackedPages[i].baseAddr == addr) {
            m_trackedPages.erase(m_trackedPages.begin() + i);
            continue;
        }
        i++;
    }

    LeaveCriticalSection(&m_cs);
}

void AllocTracker::OnMapView(void* baseAddr, SIZE_T size, ULONG protect)
{
    OnAllocation(baseAddr, size, protect);
}

NTSTATUS NTAPI AllocTracker::HookedNtFreeVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType)
{
    auto orig = (NtFreeVirtualMemoryFunc)g_allocTracker->m_ntFreeTrampoline;
    if (!orig) return STATUS_NOT_IMPLEMENTED;

    NTSTATUS status = orig(ProcessHandle, BaseAddress, RegionSize, FreeType);

    if (NT_SUCCESS(status) && ProcessHandle == GetCurrentProcess() && BaseAddress && *BaseAddress) {
        // Only remove tracked pages on MEM_RELEASE; MEM_DECOMMIT may still be in use
        if (FreeType & MEM_RELEASE) {
            g_allocTracker->OnFree(*BaseAddress);
        }
    }

    return status;
}

NTSTATUS NTAPI AllocTracker::HookedNtMapViewOfSection(
    HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress,
    ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Protect)
{
    auto orig = (NtMapViewOfSectionFunc)g_allocTracker->m_ntMapViewTrampoline;
    if (!orig) return STATUS_NOT_IMPLEMENTED;

    NTSTATUS status = orig(SectionHandle, ProcessHandle, BaseAddress, ZeroBits,
        CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect);

    if (NT_SUCCESS(status) && ProcessHandle == GetCurrentProcess() && BaseAddress && *BaseAddress) {
        g_allocTracker->OnMapView(*BaseAddress, ViewSize ? *ViewSize : 0, Protect);
    }

    return status;
}
