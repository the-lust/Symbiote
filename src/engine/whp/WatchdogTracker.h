#pragma once
#include <windows.h>
#include <vector>
#include <unordered_map>
#include "Logger.h"

class Partition;
class EptExecHook;

struct WatchdogEntry {
    uint64_t gpa;
    uint64_t rip;
    uint32_t threadId;
    uint32_t hitCount;
    bool active;
};

class WatchdogTracker {
public:
    WatchdogTracker(Logger* logger, Partition* partition, EptExecHook* eptExecHook);
    ~WatchdogTracker();

    bool Initialize();
    void Shutdown();

    bool OnThreadCreate(uint64_t startRip);

    static void OnWatchdogExec(uint64_t gpa, uint64_t rip);

    void SimulateIntegrityCheck();

    const std::vector<WatchdogEntry>& GetWatchdogs() const { return m_watchdogs; }

private:
    static WatchdogTracker* s_instance;

    Logger* m_logger;
    Partition* m_partition;
    EptExecHook* m_eptExecHook;
    bool m_initialized;

    std::vector<WatchdogEntry> m_watchdogs;
    std::unordered_map<uint64_t, size_t> m_gpaToIndex;

    bool IsLikelyWatchdog(uint64_t rip);
    uint64_t ResolveWatchdogGpa(uint64_t rip);
};
