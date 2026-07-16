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

void KernelLock::Lock()
{
    AcquireSRWLockExclusive(&m_globalLock);
    m_ownerThreadId = GetCurrentThreadId();
    m_recursionCount++;
}

void KernelLock::Unlock()
{
    if (m_recursionCount > 0) m_recursionCount--;
    if (m_recursionCount == 0) m_ownerThreadId = 0;
    ReleaseSRWLockExclusive(&m_globalLock);
}

bool KernelLock::TryLock()
{
    if (TryAcquireSRWLockExclusive(&m_globalLock)) {
        m_ownerThreadId = GetCurrentThreadId();
        m_recursionCount++;
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
