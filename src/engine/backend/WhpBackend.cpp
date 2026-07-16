#include "WhpBackend.h"
#include "whp/Partition.h"
#include "whp/VcpuManager.h"
#include "whp/ExitDispatcher.h"
#include "whp/CpuidHandler.h"
#include "whp/RdtscHandler.h"
#include "whp/MsrHandler.h"
#include "whp/EptExecHook.h"
#include "whp/EptSplitView.h"
#include "whp/EptHook.h"
#include "whp/KernelLock.h"
#include "whp/GuestPageTable.h"
#include <WinHvPlatform.h>

WhpBackend::WhpBackend(Logger* logger)
    : m_logger(logger)
    , m_partition(nullptr)
    , m_vcpuManager(nullptr)
    , m_exitDispatcher(nullptr)
    , m_vcpuIndex(0)
    , m_exitCount(0)
    , m_syscallCount(0)
    , m_running(false)
{
}

WhpBackend::~WhpBackend()
{
    Stop();
    delete m_vcpuManager;
    delete m_partition;
}

void WhpBackend::WireHandlers(CpuidHandler* cpuid, RdtscHandler* rdtsc, MsrHandler* msr,
                               MagicCpuid* magic, ExceptionHandler* exc, EptExecHook* eptExec,
                               EptSplitView* eptSplit, KernelLock* kernelLock)
{
    (void)cpuid; (void)rdtsc; (void)msr; (void)magic;
    (void)exc; (void)eptExec; (void)eptSplit; (void)kernelLock;
}

bool WhpBackend::Initialize()
{
    return m_partition && m_vcpuManager;
}

bool WhpBackend::Run()
{
    if (!m_vcpuManager) return false;
    m_running = true;
    m_vcpuManager->Run(m_vcpuIndex);
    m_running = false;
    return true;
}

bool WhpBackend::Stop()
{
    m_running = false;
    return true;
}

bool WhpBackend::SingleStep()
{
    return false;
}

uint64_t WhpBackend::ReadRegister(CpuReg reg)
{
    (void)reg;
    return 0;
}

bool WhpBackend::WriteRegister(CpuReg reg, uint64_t value)
{
    (void)reg; (void)value;
    return false;
}

bool WhpBackend::ReadMemory(uint64_t addr, void* buf, size_t size)
{
    if (!buf || size == 0) return false;
    __try {
        memcpy(buf, (const void*)addr, size);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool WhpBackend::WriteMemory(uint64_t addr, const void* buf, size_t size)
{
    if (!buf || size == 0) return false;
    DWORD oldProtect;
    if (!VirtualProtect((LPVOID)addr, size, PAGE_READWRITE, &oldProtect))
        return false;
    __try {
        memcpy((void*)addr, buf, size);
        VirtualProtect((LPVOID)addr, size, oldProtect, &oldProtect);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        VirtualProtect((LPVOID)addr, size, oldProtect, &oldProtect);
        return false;
    }
}

uint64_t WhpBackend::GetPhysicalAddress(uint64_t virtualAddr)
{
    return virtualAddr;
}

bool WhpBackend::MapGuestMemory(uint64_t gpa, void* hostVa, size_t size, bool exec, bool write)
{
    if (!m_partition) return false;
    WHV_MAP_GPA_RANGE_FLAGS flags = WHvMapGpaRangeFlagRead;
    if (write) flags |= WHvMapGpaRangeFlagWrite;
    if (exec) flags |= WHvMapGpaRangeFlagExecute;
    return SUCCEEDED(WHvMapGpaRange(m_partition->GetHandle(), hostVa, gpa, size, flags));
}

bool WhpBackend::UnmapGuestMemory(uint64_t gpa, size_t size)
{
    if (!m_partition) return false;
    return SUCCEEDED(WHvUnmapGpaRange(m_partition->GetHandle(), gpa, size));
}

bool WhpBackend::SetBreakpoint(uint64_t addr)
{
    (void)addr;
    return false;
}

bool WhpBackend::RemoveBreakpoint(uint64_t addr)
{
    (void)addr;
    return false;
}

bool WhpBackend::HasBreakpoint(uint64_t addr) const
{
    (void)addr;
    return false;
}

bool WhpBackend::IsRunning() const
{
    return m_running;
}

uint64_t WhpBackend::GetExitCount() const
{
    return m_exitCount;
}

uint64_t WhpBackend::GetSyscallCount() const
{
    return m_syscallCount;
}

bool WhpBackend::SaveState(std::vector<uint8_t>& buffer)
{
    (void)buffer;
    return false;
}

bool WhpBackend::RestoreState(const std::vector<uint8_t>& buffer)
{
    (void)buffer;
    return false;
}
