#pragma once
#include <windows.h>
#include "Logger.h"

class VcpuManager;

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
    ThreadScheduler(Logger* logger, VcpuManager* vcpuMgr, int numVcpus);
    ~ThreadScheduler();

    bool Start();
    bool Stop();
    bool IsRunning() const { return m_running; }

    SyncBarrier* GetBarrier() { return m_barrier; }
    ExitCoordinator* GetCoordinator() { return m_coordinator; }

private:
    Logger* m_logger;
    VcpuManager* m_vcpuMgr;
    int m_numVcpus;
    bool m_running;
    HANDLE m_schedulerThread;

    SyncBarrier* m_barrier;
    ExitCoordinator* m_coordinator;

    static DWORD WINAPI SchedulerThreadProc(LPVOID lpParam);
    void SchedulerLoop();
};