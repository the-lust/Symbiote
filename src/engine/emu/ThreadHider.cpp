#include "ThreadHider.h"
#include <tlhelp32.h>
#include <cstring>
#include <winternl.h>

ThreadHider::ThreadHider(Logger* logger)
    : m_logger(logger), m_initialized(false),
      m_originalCreateToolhelp32Snapshot(nullptr),
      m_originalThread32First(nullptr),
      m_originalThread32Next(nullptr),
      m_hooksInstalled(false)
{
    memset(m_origBytesSnapshot, 0, sizeof(m_origBytesSnapshot));
    memset(m_origBytesFirst, 0, sizeof(m_origBytesFirst));
    memset(m_origBytesNext, 0, sizeof(m_origBytesNext));
}

ThreadHider::~ThreadHider()
{
    Shutdown();
}

bool ThreadHider::Initialize()
{
    if (m_initialized) return true;
    if (!InstallHooks()) {
        m_logger->Trace(LOG_WARNING, "ThreadHider: hook installation failed");
    }
    m_initialized = true;
    m_logger->Trace(LOG_INFO, "ThreadHider initialized (hooks=%s)", m_hooksInstalled ? "active" : "failed");
    return true;
}

void ThreadHider::Shutdown()
{
    if (!m_initialized) return;
    RemoveHooks();
    m_hiddenThreads.clear();
    m_hiddenProcesses.clear();
    m_initialized = false;
    m_logger->Trace(LOG_INFO, "ThreadHider shutdown");
}

void ThreadHider::HideThread(uint32_t threadId)
{
    if (threadId == 0) return;
    for (auto id : m_hiddenThreads) {
        if (id == threadId) return;
    }
    m_hiddenThreads.push_back(threadId);
}

void ThreadHider::UnhideThread(uint32_t threadId)
{
    auto it = std::remove(m_hiddenThreads.begin(), m_hiddenThreads.end(), threadId);
    m_hiddenThreads.erase(it, m_hiddenThreads.end());
}

void ThreadHider::HideProcess(uint32_t processId)
{
    if (processId == 0) return;
    for (auto id : m_hiddenProcesses) {
        if (id == processId) return;
    }
    m_hiddenProcesses.push_back(processId);
}

void ThreadHider::UnhideProcess(uint32_t processId)
{
    auto it = std::remove(m_hiddenProcesses.begin(), m_hiddenProcesses.end(), processId);
    m_hiddenProcesses.erase(it, m_hiddenProcesses.end());
}

bool ThreadHider::IsThreadHidden(uint32_t threadId) const
{
    for (auto id : m_hiddenThreads) {
        if (id == threadId) return true;
    }
    return false;
}

bool ThreadHider::IsProcessHidden(uint32_t processId) const
{
    for (auto id : m_hiddenProcesses) {
        if (id == processId) return true;
    }
    return false;
}

bool ThreadHider::HandleSystemProcessInformation(uint64_t infoBuffer, uint32_t infoLength, uint64_t* returnLength, uint64_t* result)
{
    if (!infoBuffer || infoLength < sizeof(ULONG)) return false;

    uint8_t* buffer = (uint8_t*)(uintptr_t)infoBuffer;
    uint32_t originalSize = *(uint32_t*)buffer;
    if (originalSize == 0) return false;

    uint8_t* src = buffer;
    uint8_t* dst = buffer;
    uint32_t totalRead = 0;
    uint32_t totalWritten = 0;

    while (totalRead < originalSize) {
        SYSTEM_PROCESS_INFORMATION* spi = (SYSTEM_PROCESS_INFORMATION*)(src + totalRead);
        ULONG nextOffset = spi->NextEntryOffset;
        uint32_t entrySize = nextOffset > 0 ? nextOffset : (originalSize - totalRead);
        if (entrySize == 0) break;

        bool hideProcess = IsProcessHidden((uint32_t)(uintptr_t)spi->UniqueProcessId);

        // If not hiding this process, copy it to the destination
        if (!hideProcess) {
            if (dst != src + totalRead) {
                memmove(dst, src + totalRead, entrySize);
            }
            // Zero out thread entries that are hidden
            PSYSTEM_THREAD_INFORMATION sti = (PSYSTEM_THREAD_INFORMATION)(dst + sizeof(SYSTEM_PROCESS_INFORMATION));
            ULONG threadCount = spi->NumberOfThreads;
            ULONG keptThreads = threadCount;

            for (ULONG t = 0; t < threadCount; t++) {
                if (IsThreadHidden((uint32_t)(uintptr_t)sti[t].ClientId.UniqueThread)) {
                    keptThreads--;
                }
            }

            if (keptThreads != threadCount) {
                // Compact thread entries
                ULONG stiWritten = 0;
                for (ULONG t = 0; t < threadCount; t++) {
                    if (!IsThreadHidden((uint32_t)(uintptr_t)sti[t].ClientId.UniqueThread)) {
                        if (stiWritten < t) {
                            memcpy(&sti[stiWritten], &sti[t], sizeof(SYSTEM_THREAD_INFORMATION));
                        }
                        stiWritten++;
                    }
                }
                ((SYSTEM_PROCESS_INFORMATION*)dst)->NumberOfThreads = keptThreads;
            }

            dst += entrySize;
            totalWritten += entrySize;
        }

        if (nextOffset == 0) break;
        totalRead += nextOffset;
    }

    *(uint32_t*)buffer = totalWritten;
    if (returnLength) *returnLength = totalWritten;
    if (result) *result = 0;
    return true;
}

// ── 12-byte patching helpers ──────────────────────────────────────

static bool Install12ByteHook(void* target, void* hook, uint8_t* backup)
{
    DWORD old;
    if (!VirtualProtect(target, 12, PAGE_EXECUTE_READWRITE, &old))
        return false;
    memcpy(backup, target, 12);
    uint8_t* p = (uint8_t*)target;
    p[0] = 0x48; p[1] = 0xB8;
    *(uint64_t*)&p[2] = (uint64_t)(uintptr_t)hook;
    p[10] = 0xFF; p[11] = 0xE0;
    VirtualProtect(target, 12, old, &old);
    FlushInstructionCache(GetCurrentProcess(), target, 12);
    return true;
}

static void Remove12ByteHook(void* target, uint8_t* backup)
{
    DWORD old;
    VirtualProtect(target, 12, PAGE_EXECUTE_READWRITE, &old);
    memcpy(target, backup, 12);
    VirtualProtect(target, 12, old, &old);
    FlushInstructionCache(GetCurrentProcess(), target, 12);
}

// ── Hook trampolines ──────────────────────────────────────────────

typedef HANDLE (WINAPI* RealCreateToolhelp32Snapshot_t)(DWORD, DWORD);
typedef BOOL   (WINAPI* RealThread32First_t)(HANDLE, LPTHREADENTRY32);
typedef BOOL   (WINAPI* RealThread32Next_t)(HANDLE, LPTHREADENTRY32);

static ThreadHider* g_threadHiderInstance = nullptr;

extern "C" HANDLE WINAPI HookedCreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID)
{
    RealCreateToolhelp32Snapshot_t real = (RealCreateToolhelp32Snapshot_t)
        (g_threadHiderInstance ? g_threadHiderInstance->m_originalCreateToolhelp32Snapshot : nullptr);
    if (!real) return INVALID_HANDLE_VALUE;
    return real(dwFlags, th32ProcessID);
}

extern "C" BOOL WINAPI HookedThread32First(HANDLE hSnapshot, LPTHREADENTRY32 lpte)
{
    RealThread32First_t real = (RealThread32First_t)
        (g_threadHiderInstance ? g_threadHiderInstance->m_originalThread32First : nullptr);
    if (!real) return FALSE;

    for (;;) {
        if (!real(hSnapshot, lpte)) return FALSE;
        if (!g_threadHiderInstance || !g_threadHiderInstance->IsThreadHidden(lpte->th32ThreadID))
            return TRUE;
    }
}

extern "C" BOOL WINAPI HookedThread32Next(HANDLE hSnapshot, LPTHREADENTRY32 lpte)
{
    RealThread32Next_t real = (RealThread32Next_t)
        (g_threadHiderInstance ? g_threadHiderInstance->m_originalThread32Next : nullptr);
    if (!real) return FALSE;

    for (;;) {
        if (!real(hSnapshot, lpte)) return FALSE;
        if (!g_threadHiderInstance || !g_threadHiderInstance->IsThreadHidden(lpte->th32ThreadID))
            return TRUE;
    }
}

bool ThreadHider::InstallHooks()
{
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        m_logger->Trace(LOG_WARNING, "ThreadHider: cannot find kernel32.dll");
        return false;
    }

    void* createSnap = GetProcAddress(hKernel32, "CreateToolhelp32Snapshot");
    void* th32First  = GetProcAddress(hKernel32, "Thread32First");
    void* th32Next   = GetProcAddress(hKernel32, "Thread32Next");

    if (!createSnap || !th32First || !th32Next) {
        m_logger->Trace(LOG_WARNING, "ThreadHider: cannot find toolhelp exports");
        return false;
    }

    g_threadHiderInstance = this;

    bool ok = true;
    ok = ok && Install12ByteHook(createSnap, HookedCreateToolhelp32Snapshot, m_origBytesSnapshot);
    ok = ok && Install12ByteHook(th32First,  HookedThread32First,  m_origBytesFirst);
    ok = ok && Install12ByteHook(th32Next,   HookedThread32Next,   m_origBytesNext);

    if (ok) {
        m_originalCreateToolhelp32Snapshot = createSnap;
        m_originalThread32First = th32First;
        m_originalThread32Next = th32Next;
        m_hooksInstalled = true;
        m_logger->Trace(LOG_INFO, "ThreadHider: inline hooks installed (3 functions)");
    } else {
        m_logger->Trace(LOG_WARNING, "ThreadHider: some hooks failed");
    }

    return ok;
}

bool ThreadHider::RemoveHooks()
{
    if (!m_hooksInstalled) return true;

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32) {
        void* createSnap = GetProcAddress(hKernel32, "CreateToolhelp32Snapshot");
        void* th32First  = GetProcAddress(hKernel32, "Thread32First");
        void* th32Next   = GetProcAddress(hKernel32, "Thread32Next");

        if (createSnap) Remove12ByteHook(createSnap, m_origBytesSnapshot);
        if (th32First)  Remove12ByteHook(th32First,  m_origBytesFirst);
        if (th32Next)   Remove12ByteHook(th32Next,   m_origBytesNext);
    }

    g_threadHiderInstance = nullptr;
    m_hooksInstalled = false;
    m_logger->Trace(LOG_INFO, "ThreadHider: hooks removed");
    return true;
}
