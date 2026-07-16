#pragma once
#include <cstdint>
#include <windows.h>
#include "Logger.h"

class IKernelBackend;
class ConfigParser;
class ProcessEmu;
class MemoryEmu;
class FileEmu;
class TimingEmu;
class RegistryEmu;
class CryptoEmu;
class VirtualState;
class ThreadManager;
class SectionEmu;
class ObjectEmu;
class ModuleCloak;
class PeLoader;
class DeviceIoEmu;

class MinimalKernel {
public:
    MinimalKernel(Logger* logger, IKernelBackend* backend);
    ~MinimalKernel();

    bool Initialize();
    void Shutdown();

    void LoadFromConfig(ConfigParser* config);
    void BuildVirtualProcessList();

    bool HandleSyscall(uint64_t syscallNumber, uint64_t* args, uint64_t* result);

    static bool DispatchThunk(uint64_t syscallNumber, uint64_t* args, uint64_t* result);

private:
    static MinimalKernel* s_instance;

    Logger* m_logger;
    IKernelBackend* m_backend;
    bool m_initialized;

    // Owned subsystems
    ProcessEmu* m_processEmu;
    MemoryEmu* m_memoryEmu;
    FileEmu* m_fileEmu;
    TimingEmu* m_timingEmu;
    RegistryEmu* m_registryEmu;
    CryptoEmu* m_cryptoEmu;
    VirtualState* m_virtualState;
    ThreadManager* m_threadManager;
    SectionEmu* m_sectionEmu;
    ObjectEmu* m_objectEmu;
    ModuleCloak* m_moduleCloak;
    PeLoader* m_peLoader;

    DeviceIoEmu* GetDeviceIoEmu() { return m_deviceIoEmu; }
    DeviceIoEmu* m_deviceIoEmu;

    // Config flags
    bool m_spoofProcess;
    bool m_spoofRegistry;
    bool m_spoofFile;
    bool m_spoofTiming;
    bool m_spoofToken;
    bool m_spoofThread;
    bool m_cloakModule;
};
