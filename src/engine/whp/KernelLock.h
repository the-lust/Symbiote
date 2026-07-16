#pragma once
#include <windows.h>
#include <cstdint>
#include <vector>

class KernelLock {
public:
    explicit KernelLock(uint32_t vcpuCount = 1);
    ~KernelLock();

    void Lock();         // exclusive (syscall dispatch, state change)
    void Unlock();       // exclusive release
    bool TryLock();      // exclusive try

    void LockExclusive() { Lock(); }
    void UnlockExclusive() { Unlock(); }
    bool TryLockExclusive() { return TryLock(); }

    void LockShared(uint32_t vcpuIndex);
    void UnlockShared(uint32_t vcpuIndex);
    bool TryLockShared(uint32_t vcpuIndex);

    bool IsHeldByCurrentThread() const;

private:
    SRWLOCK m_globalLock;
    std::vector<SRWLOCK> m_perVcpuLocks;
    DWORD m_ownerThreadId;
    uint32_t m_recursionCount;
    uint32_t m_vcpuCount;
};
