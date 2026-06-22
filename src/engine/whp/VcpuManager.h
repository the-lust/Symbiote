#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include "Logger.h"

class Partition;
class ExitDispatcher;
class CpuidHandler;
class RdtscHandler;
class MsrHandler;
class CpuProfile;
class MagicCpuid;
class SoGenEmulator;
class ExceptionHandler;

class VcpuManager {
public:
    VcpuManager(Logger* logger, Partition* partition, ExitDispatcher* exitDispatcher,
                CpuidHandler* cpuidHandler, RdtscHandler* rdtscHandler,
                MsrHandler* msrHandler, CpuProfile* cpuProfile);
    ~VcpuManager();

    bool CreateVcpu(uint32_t vcpuIndex);
    bool Run(uint32_t vcpuIndex);
    void Stop(uint32_t vcpuIndex);

    void SetMagicCpuid(MagicCpuid* magic) { m_magicCpuid = magic; }
    void SetSoGenEmulator(SoGenEmulator* emu) { m_soGenEmulator = emu; }
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
    CpuProfile* m_cpuProfile;
    MagicCpuid* m_magicCpuid;
    SoGenEmulator* m_soGenEmulator;
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
