#include "WatchdogTracker.h"
#include "EptExecHook.h"
#include "Partition.h"

WatchdogTracker* WatchdogTracker::s_instance = nullptr;

WatchdogTracker::WatchdogTracker(Logger* logger, Partition* partition, EptExecHook* eptExecHook)
    : m_logger(logger), m_partition(partition), m_eptExecHook(eptExecHook), m_initialized(false)
{
}

WatchdogTracker::~WatchdogTracker()
{
    Shutdown();
}

bool WatchdogTracker::Initialize()
{
    if (m_initialized) return true;

    if (!m_logger || !m_partition || !m_eptExecHook) {
        if (m_logger) {
            m_logger->Trace(LOG_WARNING, "WatchdogTracker: null dependency (logger=%p partition=%p hook=%p)",
                (void*)m_logger, (void*)m_partition, (void*)m_eptExecHook);
        }
        return false;
    }

    s_instance = this;

    m_initialized = true;
    m_logger->Trace(LOG_INFO, "WatchdogTracker: initialized");
    return true;
}

void WatchdogTracker::Shutdown()
{
    if (!m_initialized) return;

    for (auto& entry : m_watchdogs) {
        if (entry.active && m_eptExecHook) {
            m_eptExecHook->UnregisterPageHook(entry.gpa);
        }
    }

    m_watchdogs.clear();
    m_gpaToIndex.clear();
    s_instance = nullptr;
    m_initialized = false;

    if (m_logger) {
        m_logger->Trace(LOG_INFO, "WatchdogTracker: shutdown");
    }
}

bool WatchdogTracker::IsLikelyWatchdog(uint64_t rip)
{
    if (rip == 0) return false;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((LPCVOID)rip, &mbi, sizeof(mbi)) == 0) {
        return true;
    }

    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Type == MEM_IMAGE) return false;

    return true;
}

uint64_t WatchdogTracker::ResolveWatchdogGpa(uint64_t rip)
{
    (void)m_partition;
    return rip & ~0xFFFULL;
}

bool WatchdogTracker::OnThreadCreate(uint64_t startRip)
{
    if (!m_initialized) return false;
    if (!IsLikelyWatchdog(startRip)) return false;

    uint64_t gpa = ResolveWatchdogGpa(startRip);
    if (!gpa) return false;

    auto it = m_gpaToIndex.find(gpa);
    if (it != m_gpaToIndex.end()) {
        WatchdogEntry& entry = m_watchdogs[it->second];
        entry.hitCount++;
        entry.rip = startRip;
        entry.threadId = GetCurrentThreadId();

        m_logger->Trace(LOG_INFO, "WatchdogTracker: re-detected watchdog at GPA %llx RIP %llx (hit %u)",
            gpa, startRip, entry.hitCount);
        return true;
    }

    WatchdogEntry entry;
    entry.gpa = gpa;
    entry.rip = startRip;
    entry.threadId = GetCurrentThreadId();
    entry.hitCount = 1;
    entry.active = true;
    m_watchdogs.push_back(entry);
    m_gpaToIndex[gpa] = m_watchdogs.size() - 1;

    m_eptExecHook->RegisterPageHook(gpa, OnWatchdogExec);

    m_logger->Trace(LOG_INFO, "WatchdogTracker: detected watchdog thread at GPA %llx RIP %llx (thread %u)",
        gpa, startRip, entry.threadId);

    return true;
}

void WatchdogTracker::OnWatchdogExec(uint64_t gpa, uint64_t rip)
{
    if (!s_instance) return;

    auto it = s_instance->m_gpaToIndex.find(gpa);
    if (it == s_instance->m_gpaToIndex.end()) return;

    WatchdogEntry& entry = s_instance->m_watchdogs[it->second];
    entry.hitCount++;

    s_instance->m_logger->Trace(LOG_INFO,
        "WatchdogTracker: EPT exec hit on GPA %llx at RIP %llx (total hits %u)",
        gpa, rip, entry.hitCount);
}

void WatchdogTracker::SimulateIntegrityCheck()
{
    if (!m_initialized) return;

    m_logger->Trace(LOG_INFO, "WatchdogTracker: simulating integrity check on %zu tracked pages",
        m_watchdogs.size());

    for (auto& entry : m_watchdogs) {
        if (!entry.active) continue;

        m_logger->Trace(LOG_INFO, "WatchdogTracker: integrity verify GPA %llx (hits %u)",
            entry.gpa, entry.hitCount);

        if (m_eptExecHook->HasHook(entry.gpa)) {
            m_eptExecHook->UnregisterPageHook(entry.gpa);
            m_eptExecHook->RegisterPageHook(entry.gpa, OnWatchdogExec);
        }
    }

    m_logger->Trace(LOG_INFO, "WatchdogTracker: integrity check complete");
}
