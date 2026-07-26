#include "KernelLock.h"

KernelLock::KernelLock(uint32_t vcpuCount)
    : m_globalLock(SRWLOCK_INIT)
    , m_ownerThreadId(0)
    , m_recursionCount(0)
    , m_vcpuCount(vcpuCount)
{
    m_perVcpuLocks.resize(vcpuCount);
    for (auto& lock : m_perVcpuLocks)
        InitializeSRWLock(&lock);
}

KernelLock::~KernelLock()
{
}

// SRWLOCK does not support recursive acquisition (unlike a CRITICAL_SECTION) — a second
// AcquireSRWLockExclusive from the thread already holding it deadlocks permanently. The
// class's own IsHeldByCurrentThread()/m_recursionCount API implies reentrancy is supported,
// so implement it explicitly here: only take the real lock on the outermost Lock() call from
// a given thread, and only release it once the matching Unlock() count reaches zero.
// m_ownerThreadId/m_recursionCount are only ever touched while m_globalLock is held (either
// by this thread already owning it, or immediately after acquiring it), so no separate lock
// is needed to protect them.
void KernelLock::Lock()
{
    DWORD tid = GetCurrentThreadId();
    if (m_ownerThreadId == tid && m_recursionCount > 0) {
        m_recursionCount++;
        return;
    }
    AcquireSRWLockExclusive(&m_globalLock);
    m_ownerThreadId = tid;
    m_recursionCount = 1;
}

void KernelLock::Unlock()
{
    if (m_recursionCount > 0) m_recursionCount--;
    if (m_recursionCount == 0) {
        m_ownerThreadId = 0;
        ReleaseSRWLockExclusive(&m_globalLock);
    }
}

bool KernelLock::TryLock()
{
    DWORD tid = GetCurrentThreadId();
    if (m_ownerThreadId == tid && m_recursionCount > 0) {
        m_recursionCount++;
        return true;
    }
    if (TryAcquireSRWLockExclusive(&m_globalLock)) {
        m_ownerThreadId = tid;
        m_recursionCount = 1;
        return true;
    }
    return false;
}

void KernelLock::LockShared(uint32_t vcpuIndex)
{
    if (vcpuIndex >= m_vcpuCount) vcpuIndex = 0;
    AcquireSRWLockShared(&m_perVcpuLocks[vcpuIndex]);
}

void KernelLock::UnlockShared(uint32_t vcpuIndex)
{
    if (vcpuIndex >= m_vcpuCount) vcpuIndex = 0;
    ReleaseSRWLockShared(&m_perVcpuLocks[vcpuIndex]);
}

bool KernelLock::TryLockShared(uint32_t vcpuIndex)
{
    if (vcpuIndex >= m_vcpuCount) vcpuIndex = 0;
    return TryAcquireSRWLockShared(&m_perVcpuLocks[vcpuIndex]) != 0;
}

bool KernelLock::IsHeldByCurrentThread() const
{
    return m_ownerThreadId == GetCurrentThreadId() && m_recursionCount > 0;
}
