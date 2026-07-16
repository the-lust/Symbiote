#pragma once
#include <windows.h>
#include <cstdint>

class KernelLock {
public:
    KernelLock();
    ~KernelLock();

    void Lock();
    void Unlock();
    bool TryLock();
    bool IsHeldByCurrentThread() const;

private:
    CRITICAL_SECTION m_cs;
    DWORD m_ownerThreadId;
    uint32_t m_recursionCount;
};
