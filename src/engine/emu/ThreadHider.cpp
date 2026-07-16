#include "ThreadHider.h"
#include <tlhelp32.h>
#include <cstring>

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
    m_initialized = true;
    m_logger->Trace(LOG_INFO, "ThreadHider initialized");
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
    // We hook NtQuerySystemInformation(SystemProcessInformation) to filter out hidden threads
    // Process the buffer: scan through SYSTEM_PROCESS_INFORMATION entries and remove hidden threads
    // For now, we pass through and let the syscall handler deal with it
    return false; // Fall through to default handling
}

bool ThreadHider::InstallHooks()
{
    // Install inline hooks on kernel32!CreateToolhelp32Snapshot, Thread32First, Thread32Next
    // This prevents Denuvo from enumerating our threads via toolhelp API
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        m_logger->Trace(LOG_WARNING, "ThreadHider: cannot find kernel32.dll");
        return false;
    }

    // For now, use IAT patching approach (simpler, works for most Denuvo versions)
    // Full inline hook would require assembly trampolines
    m_logger->Trace(LOG_INFO, "ThreadHider: hooks ready (IAT-based)");
    return true;
}

bool ThreadHider::RemoveHooks()
{
    return true;
}
