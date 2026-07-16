#include "ThreadScheduler.h"
#include "VcpuManager.h"
#include "KernelLock.h"

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

// ─── ExitCoordinator ──────────────────────────────────────────────────

ExitCoordinator::ExitCoordinator(Logger* logger)
    : m_logger(logger)
{
    InitializeCriticalSection(&m_cs);
    for (int i = 0; i < 4; i++) m_exitRequested[i] = false;
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

// ─── ThreadScheduler (Round-Robin BEL) ────────────────────────────────

ThreadScheduler::ThreadScheduler(Logger* logger, VcpuManager* vcpuMgr, int numVcpus, KernelLock* kernelLock)
    : m_logger(logger), m_vcpuMgr(vcpuMgr), m_kernelLock(kernelLock),
      m_numVcpus(numVcpus), m_running(false), m_schedulerThread(nullptr),
      m_barrier(nullptr), m_coordinator(nullptr), m_nextPickIndex(0)
{
    InitializeCriticalSection(&m_readyCs);
    m_barrier = new SyncBarrier(logger, numVcpus);
    m_coordinator = new ExitCoordinator(logger);
}

ThreadScheduler::~ThreadScheduler()
{
    Stop();
    delete m_coordinator;
    delete m_barrier;
    DeleteCriticalSection(&m_readyCs);
}

bool ThreadScheduler::Start()
{
    if (m_running) return true;
    m_running = true;

    m_schedulerThread = CreateThread(nullptr, 0, SchedulerThreadProc, this, 0, nullptr);
    if (!m_schedulerThread) {
        m_logger->Trace(LOG_ERROR, "ThreadScheduler: failed to create scheduler thread (GLE=%u)", GetLastError());
        m_running = false;
        return false;
    }

    m_logger->Trace(LOG_INFO, "ThreadScheduler: started (%d VCPUs)", m_numVcpus);
    return true;
}

bool ThreadScheduler::Stop()
{
    if (!m_running) return true;
    m_running = false;

    if (m_schedulerThread) {
        // Signal all VCPUs to stop
        for (int i = 0; i < m_numVcpus; i++) {
            m_coordinator->RequestExit(i);
        }
        // Cancel any running VCPU
        for (int i = 0; i < m_numVcpus; i++) {
            // VcpuManager handles its own cancellation
        }
        WaitForSingleObject(m_schedulerThread, 3000);
        CloseHandle(m_schedulerThread);
        m_schedulerThread = nullptr;
    }

    m_logger->Trace(LOG_INFO, "ThreadScheduler: stopped");
    return true;
}

void ThreadScheduler::MarkReady(uint32_t vcpuIndex)
{
    EnterCriticalSection(&m_readyCs);
    // Check if already queued
    for (auto idx : m_readyQueue) {
        if (idx == vcpuIndex) {
            LeaveCriticalSection(&m_readyCs);
            return;
        }
    }
    m_readyQueue.push_back(vcpuIndex);
    LeaveCriticalSection(&m_readyCs);
}

uint32_t ThreadScheduler::PickNextVcpu()
{
    EnterCriticalSection(&m_readyCs);
    if (m_readyQueue.empty()) {
        LeaveCriticalSection(&m_readyCs);
        return UINT32_MAX;
    }
    // Round-robin: pick the next ready VCPU
    if (m_nextPickIndex >= m_readyQueue.size()) m_nextPickIndex = 0;
    uint32_t picked = m_readyQueue[m_nextPickIndex];
    m_readyQueue.erase(m_readyQueue.begin() + m_nextPickIndex);
    LeaveCriticalSection(&m_readyCs);
    return picked;
}

bool ThreadScheduler::SetVcpuAffinity(uint32_t vcpuIndex, uint32_t idealProcessor)
{
    (void)vcpuIndex;
    (void)idealProcessor;
    // Guest thread affinity is set via NtSetInformationThread — we forward
    // that to the host thread for the corresponding VCPU.
    // Placeholder: will be implemented when guest thread affinity syscalls are routed.
    return false;
}

DWORD WINAPI ThreadScheduler::SchedulerThreadProc(LPVOID lpParam)
{
    ThreadScheduler* self = (ThreadScheduler*)lpParam;
    self->SchedulerLoop();
    return 0;
}

void ThreadScheduler::SchedulerLoop()
{
    m_logger->Trace(LOG_INFO, "ThreadScheduler: scheduler loop started");

    while (m_running) {
        // Sleep 10ms between scheduling ticks for now (reactive to VM-exits,
        // not timer-based — we respond when VCPUs signal readiness).
        // In a fully reactive design, MarkReady would pulse an event and
        // this thread would wait on that event. For now, just brief sleep
        // to keep the thread alive.
        Sleep(10);

        // Every tick, check if any VCPUs should be preempted (future work)
        // Currently, scheduling is cooperative: a VCPU runs until it VM-exits.
    }

    m_logger->Trace(LOG_INFO, "ThreadScheduler: scheduler loop stopped");
}
