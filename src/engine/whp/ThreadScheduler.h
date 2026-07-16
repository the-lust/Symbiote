#pragma once
#include <windows.h>
#include "Logger.h"
#include <vector>

class VcpuManager;
class KernelLock;

class SyncBarrier {
public:
    SyncBarrier(Logger* logger, int numThreads);
    ~SyncBarrier();

    bool Wait(DWORD timeoutMs = INFINITE);

private:
    Logger* m_logger;
    int m_numThreads;
    int m_count;
    CRITICAL_SECTION m_cs;
    CONDITION_VARIABLE m_cv;
};

class ExitCoordinator {
public:
    ExitCoordinator(Logger* logger);
    ~ExitCoordinator();

    bool RequestExit(uint32_t vcpuIndex);
    bool IsExitRequested(uint32_t vcpuIndex) const;
    void Reset(uint32_t vcpuIndex);

private:
    Logger* m_logger;
    bool m_exitRequested[4];
    mutable CRITICAL_SECTION m_cs;
};

class ThreadScheduler {
public:
    ThreadScheduler(Logger* logger, VcpuManager* vcpuMgr, int numVcpus, KernelLock* kernelLock);
    ~ThreadScheduler();

    bool Start();
    bool Stop();
    bool IsRunning() const { return m_running; }

    // Round-robin ready queue
    void MarkReady(uint32_t vcpuIndex);
    uint32_t PickNextVcpu();

    // Per-VCPU thread affinity
    bool SetVcpuAffinity(uint32_t vcpuIndex, uint32_t idealProcessor);

    SyncBarrier* GetBarrier() { return m_barrier; }
    ExitCoordinator* GetCoordinator() { return m_coordinator; }

private:
    Logger* m_logger;
    VcpuManager* m_vcpuMgr;
    KernelLock* m_kernelLock;
    int m_numVcpus;
    bool m_running;
    HANDLE m_schedulerThread;

    SyncBarrier* m_barrier;
    ExitCoordinator* m_coordinator;

    // Round-robin state (guarded by m_readyCs)
    CRITICAL_SECTION m_readyCs;
    std::vector<uint32_t> m_readyQueue;
    uint32_t m_nextPickIndex;

    static DWORD WINAPI SchedulerThreadProc(LPVOID lpParam);
    void SchedulerLoop();
};
