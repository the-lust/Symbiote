#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include "Logger.h"

#include "CpuidHandler.h"

class Partition;
class ExitDispatcher;
class RdtscHandler;
class MsrHandler;
class MagicCpuid;
class ExceptionHandler;
using SyscallHandler = bool(uint64_t syscallNumber, uint64_t* args, uint64_t* result);

class VcpuManager {
public:
    VcpuManager(Logger* logger, Partition* partition, ExitDispatcher* exitDispatcher,
                CpuidHandler* cpuidHandler, RdtscHandler* rdtscHandler,
                MsrHandler* msrHandler);
    ~VcpuManager();

    bool CreateVcpu(uint32_t vcpuIndex);
    bool Run(uint32_t vcpuIndex);
    void Stop(uint32_t vcpuIndex);

    void SetMagicCpuid(MagicCpuid* magic) {
        m_magicCpuid = magic;
        if (m_cpuidHandler) {
            m_cpuidHandler->SetMagicCpuid(magic);
        }
    }
    void SetSyscallHandler(SyscallHandler* handler) { m_syscallHandler = handler; }
    void SetExceptionHandler(ExceptionHandler* handler) { m_exceptionHandler = handler; }

private:
    bool SetupRegisters(uint32_t vcpuIndex);
    bool HandleExit(uint32_t vcpuIndex);
    bool LoadBootCode(uint32_t vcpuIndex);
    bool SetupSegmentRegisters(uint32_t vcpuIndex);
    bool SetupControlRegisters(uint32_t vcpuIndex);

    Logger* m_logger;
    Partition* m_partition;
    ExitDispatcher* m_exitDispatcher;
    CpuidHandler* m_cpuidHandler;
    RdtscHandler* m_rdtscHandler;
    MsrHandler* m_msrHandler;
    MagicCpuid* m_magicCpuid;
    SyscallHandler* m_syscallHandler;
    ExceptionHandler* m_exceptionHandler;

    struct VcpuContext {
        WHV_RUN_VP_EXIT_CONTEXT exitCtx;
        uint8_t* stack;
        bool running;
    };

    static const uint32_t MAX_VCPU = 20;
    VcpuContext m_vcpus[MAX_VCPU];
    uint32_t m_vcpuCount;
    bool m_bootCodeLoaded;
};
