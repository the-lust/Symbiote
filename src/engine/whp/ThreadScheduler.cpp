#include "ThreadScheduler.h"
#include "VcpuManager.h"

SyncBarrier::SyncBarrier(Logger* logger, int numThreads)
    : m_logger(logger), m_numThreads(numThreads), m_count(0)
{
    InitializeCriticalSection(&m_cs);
    InitializeConditionVariable(&m_cv);
}

SyncBarrier::~SyncBarrier()
{
    DeleteCriticalSection(&m_cs);
}

bool SyncBarrier::Wait(DWORD timeoutMs)
{
    EnterCriticalSection(&m_cs);
    m_count++;

    if (m_count >= m_numThreads) {
        m_count = 0;
        WakeAllConditionVariable(&m_cv);
        LeaveCriticalSection(&m_cs);
        return true;
    }

    BOOL result = SleepConditionVariableCS(&m_cv, &m_cs, timeoutMs);
    LeaveCriticalSection(&m_cs);

    return result != FALSE;
}

ExitCoordinator::ExitCoordinator(Logger* logger)
    : m_logger(logger)
{
    memset(m_exitRequested, 0, sizeof(m_exitRequested));
    InitializeCriticalSection(&m_cs);
}

ExitCoordinator::~ExitCoordinator()
{
    DeleteCriticalSection(&m_cs);
}

bool ExitCoordinator::RequestExit(uint32_t vcpuIndex)
{
    if (vcpuIndex >= 4) return false;
    EnterCriticalSection(&m_cs);
    m_exitRequested[vcpuIndex] = true;
    LeaveCriticalSection(&m_cs);
    return true;
}

bool ExitCoordinator::IsExitRequested(uint32_t vcpuIndex) const
{
    if (vcpuIndex >= 4) return false;
    EnterCriticalSection(&m_cs);
    bool result = m_exitRequested[vcpuIndex];
    LeaveCriticalSection(&m_cs);
    return result;
}

void ExitCoordinator::Reset(uint32_t vcpuIndex)
{
    if (vcpuIndex >= 4) return;
    EnterCriticalSection(&m_cs);
    m_exitRequested[vcpuIndex] = false;
    LeaveCriticalSection(&m_cs);
}

ThreadScheduler::ThreadScheduler(Logger* logger, VcpuManager* vcpuMgr, int numVcpus)
    : m_logger(logger), m_vcpuMgr(vcpuMgr), m_numVcpus(numVcpus),
      m_running(false), m_schedulerThread(nullptr)
{
    m_barrier = new SyncBarrier(logger, numVcpus);
    m_coordinator = new ExitCoordinator(logger);
}

ThreadScheduler::~ThreadScheduler()
{
    Stop();
    delete m_barrier;
    delete m_coordinator;
}

DWORD WINAPI ThreadScheduler::SchedulerThreadProc(LPVOID lpParam)
{
    ThreadScheduler* scheduler = (ThreadScheduler*)lpParam;
    scheduler->SchedulerLoop();
    return 0;
}

void ThreadScheduler::SchedulerLoop()
{
    m_logger->Trace(LOG_INFO, "ThreadScheduler: round-robin scheduler started");

    while (m_running) {
        // wait at barrier - all VCPUs sync here
        // in real scheduler wed account for quantum etc
        // for now just a simple sync point
        m_barrier->Wait(100);

        // check if any VCPU requested coordinated exit
        for (int i = 0; i < m_numVcpus; i++) {
            if (m_coordinator->IsExitRequested((uint32_t)i)) {
                m_logger->Trace(LOG_WHP, "ThreadScheduler: VCPU %d exit requested", i);
                m_vcpuMgr->Stop((uint32_t)i);
                m_coordinator->Reset((uint32_t)i);
            }
        }

        // round-robin quantum: just yield
        SwitchToThread();
    }

    m_logger->Trace(LOG_INFO, "ThreadScheduler: stopped");
}

bool ThreadScheduler::Start()
{
    if (m_running) return true;

    m_running = true;
    m_schedulerThread = CreateThread(nullptr, 0, SchedulerThreadProc, this, 0, nullptr);
    if (!m_schedulerThread) {
        m_logger->Trace(LOG_ERROR, "ThreadScheduler: failed to create scheduler thread");
        m_running = false;
        return false;
    }

    m_logger->Trace(LOG_INFO, "ThreadScheduler: started with %d VCPUs", m_numVcpus);
    return true;
}

bool ThreadScheduler::Stop()
{
    if (!m_running) return true;

    m_running = false;
    if (m_schedulerThread) {
        WaitForSingleObject(m_schedulerThread, 1000);
        CloseHandle(m_schedulerThread);
        m_schedulerThread = nullptr;
    }

    m_logger->Trace(LOG_INFO, "ThreadScheduler: stopped");
    return true;
}