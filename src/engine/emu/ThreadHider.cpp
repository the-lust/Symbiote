#include "ThreadHider.h"
#include <tlhelp32.h>
#include <cstring>
#include <winternl.h>

ThreadHider::ThreadHider(Logger* logger)
    : m_logger(logger), m_initialized(false),
      m_originalCreateToolhelp32Snapshot(nullptr),
      m_originalThread32First(nullptr),
      m_originalThread32Next(nullptr),
      m_trampolineSnapshot(nullptr),
      m_trampolineFirst(nullptr),
      m_trampolineNext(nullptr),
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

bool ThreadHider::HandleSystemProcessInformation(uint64_t infoBuffer, uint32_t infoLength, uint32_t* returnLength, uint64_t* result)
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

        if (!hideProcess) {
            if (dst != src + totalRead) {
                memmove(dst, src + totalRead, entrySize);
            }
            PSYSTEM_THREAD_INFORMATION sti = (PSYSTEM_THREAD_INFORMATION)(dst + sizeof(SYSTEM_PROCESS_INFORMATION));
            ULONG threadCount = spi->NumberOfThreads;
            ULONG keptThreads = threadCount;

            for (ULONG t = 0; t < threadCount; t++) {
                if (IsThreadHidden((uint32_t)(uintptr_t)sti[t].ClientId.UniqueThread)) {
                    keptThreads--;
                }
            }

            if (keptThreads != threadCount) {
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
    if (returnLength) *returnLength = (uint32_t)totalWritten;
    if (result) *result = 0;
    return true;
}

// ── 12-byte detour hook with proper trampoline ───────────────────
//
// Writes:   target[0..1]  = 48 B8  (mov rax, imm64)
//           target[2..9]  = hook address
//           target[10..11]= FF E0  (jmp rax)
//
// Trampoline (allocated RX memory):
//           [0..11]  = original 12 bytes from target
//           [12..21] = 48 B8 <target+12>  (mov rax, target+12)
//           [22..23] = FF E0  (jmp rax)
//
// Returns trampoline address, or nullptr on failure.
// The hook calls the trampoline to reach the real function.

static void* InstallTrampolineHook(void* target, void* hook, uint8_t* backup)
{
    DWORD old;
    if (!VirtualProtect(target, 12, PAGE_EXECUTE_READWRITE, &old))
        return nullptr;

    memcpy(backup, target, 12);

    // Write hook at target
    uint8_t* p = (uint8_t*)target;
    p[0] = 0x48; p[1] = 0xB8;
    *(uint64_t*)&p[2] = (uint64_t)(uintptr_t)hook;
    p[10] = 0xFF; p[11] = 0xE0;

    VirtualProtect(target, 12, old, &old);
    FlushInstructionCache(GetCurrentProcess(), target, 12);

    // Allocate trampoline: 12 original bytes + 12-byte jmp to target+12
    void* trampoline = VirtualAlloc(nullptr, 24, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!trampoline) return nullptr;

    uint8_t* t = (uint8_t*)trampoline;
    memcpy(t, backup, 12);                              // original 12 bytes
    t[12] = 0x48; t[13] = 0xB8;                         // mov rax, imm64
    *(uint64_t*)&t[14] = (uint64_t)(uintptr_t)target + 12; // resume at target+12
    t[22] = 0xFF; t[23] = 0xE0;                         // jmp rax

    FlushInstructionCache(GetCurrentProcess(), trampoline, 24);
    return trampoline;
}

static void RemoveTrampolineHook(void* target, uint8_t* backup, void* trampoline)
{
    DWORD old;
    VirtualProtect(target, 12, PAGE_EXECUTE_READWRITE, &old);
    memcpy(target, backup, 12);
    VirtualProtect(target, 12, old, &old);
    FlushInstructionCache(GetCurrentProcess(), target, 12);

    if (trampoline) {
        VirtualFree(trampoline, 0, MEM_RELEASE);
    }
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

    m_trampolineSnapshot = InstallTrampolineHook(createSnap, HookedCreateToolhelp32Snapshot, m_origBytesSnapshot);
    ok = ok && (m_trampolineSnapshot != nullptr);
    if (ok) m_originalCreateToolhelp32Snapshot = m_trampolineSnapshot;

    m_trampolineFirst = InstallTrampolineHook(th32First, HookedThread32First, m_origBytesFirst);
    ok = ok && (m_trampolineFirst != nullptr);
    if (ok) m_originalThread32First = m_trampolineFirst;

    m_trampolineNext = InstallTrampolineHook(th32Next, HookedThread32Next, m_origBytesNext);
    ok = ok && (m_trampolineNext != nullptr);
    if (ok) m_originalThread32Next = m_trampolineNext;

    if (ok) {
        m_hooksInstalled = true;
        m_logger->Trace(LOG_INFO, "ThreadHider: inline hooks installed (3 functions, trampolines at %p/%p/%p)",
            m_trampolineSnapshot, m_trampolineFirst, m_trampolineNext);
    } else {
        m_logger->Trace(LOG_WARNING, "ThreadHider: some hooks failed — rolling back");
        if (m_trampolineSnapshot) RemoveTrampolineHook(createSnap, m_origBytesSnapshot, m_trampolineSnapshot);
        if (m_trampolineFirst)   RemoveTrampolineHook(th32First,  m_origBytesFirst,   m_trampolineFirst);
        if (m_trampolineNext)    RemoveTrampolineHook(th32Next,   m_origBytesNext,    m_trampolineNext);
        m_trampolineSnapshot = m_trampolineFirst = m_trampolineNext = nullptr;
        g_threadHiderInstance = nullptr;
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

        if (createSnap) RemoveTrampolineHook(createSnap, m_origBytesSnapshot, m_trampolineSnapshot);
        if (th32First)  RemoveTrampolineHook(th32First,  m_origBytesFirst,   m_trampolineFirst);
        if (th32Next)   RemoveTrampolineHook(th32Next,   m_origBytesNext,    m_trampolineNext);
    }

    m_trampolineSnapshot = m_trampolineFirst = m_trampolineNext = nullptr;
    g_threadHiderInstance = nullptr;
    m_hooksInstalled = false;
    m_logger->Trace(LOG_INFO, "ThreadHider: hooks removed");
    return true;
}
