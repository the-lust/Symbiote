#include "KernelLock.h"

KernelLock::KernelLock()
    : m_ownerThreadId(0), m_recursionCount(0)
{
    InitializeCriticalSection(&m_cs);
}

KernelLock::~KernelLock()
{
    DeleteCriticalSection(&m_cs);
}

void KernelLock::Lock()
{
    EnterCriticalSection(&m_cs);
    m_ownerThreadId = GetCurrentThreadId();
    m_recursionCount++;
}

void KernelLock::Unlock()
{
    if (m_recursionCount > 0) m_recursionCount--;
    if (m_recursionCount == 0) m_ownerThreadId = 0;
    LeaveCriticalSection(&m_cs);
}

bool KernelLock::TryLock()
{
    if (TryEnterCriticalSection(&m_cs)) {
        m_ownerThreadId = GetCurrentThreadId();
        m_recursionCount++;
        return true;
    }
    return false;
}

bool KernelLock::IsHeldByCurrentThread() const
{
    // We can't safely query CRITICAL_SECTION ownership, so track it ourselves
    return m_ownerThreadId == GetCurrentThreadId() && m_recursionCount > 0;
}
