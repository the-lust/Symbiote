#include "MinimalKernel.h"
#include "IKernelBackend.h"
#include "ConfigParser.h"
#include "emu/ProcessEmu.h"
#include "emu/MemoryEmu.h"
#include "emu/FileEmu.h"
#include "emu/TimingEmu.h"
#include "emu/RegistryEmu.h"
#include "emu/CryptoEmu.h"
#include "emu/VirtualState.h"
#include "emu/ThreadManager.h"
#include "emu/SectionEmu.h"
#include "emu/ObjectEmu.h"
#include "emu/PeLoader.h"
#include "proxy/ModuleCloak.h"

MinimalKernel* MinimalKernel::s_instance = nullptr;

MinimalKernel::MinimalKernel(Logger* logger, IKernelBackend* backend)
    : m_logger(logger), m_backend(backend), m_initialized(false),
      m_processEmu(nullptr), m_memoryEmu(nullptr), m_fileEmu(nullptr),
      m_timingEmu(nullptr), m_registryEmu(nullptr), m_cryptoEmu(nullptr),
      m_virtualState(nullptr), m_threadManager(nullptr),
      m_sectionEmu(nullptr), m_objectEmu(nullptr),
      m_moduleCloak(nullptr), m_peLoader(nullptr),
      m_spoofProcess(false), m_spoofRegistry(false), m_spoofFile(false),
      m_spoofTiming(false), m_spoofToken(false), m_spoofThread(false),
      m_cloakModule(false)
{
}

MinimalKernel::~MinimalKernel()
{
    Shutdown();
}

bool MinimalKernel::Initialize()
{
    if (m_initialized) return true;

    m_processEmu = new ProcessEmu(m_logger, m_moduleCloak);
    m_memoryEmu = new MemoryEmu(m_logger);
    m_fileEmu = new FileEmu(m_logger);
    m_timingEmu = new TimingEmu(m_logger);
    m_registryEmu = new RegistryEmu(m_logger);
    m_cryptoEmu = new CryptoEmu(m_logger);
    m_virtualState = new VirtualState(m_logger);
    m_threadManager = new ThreadManager(m_logger);
    m_sectionEmu = new SectionEmu(m_logger);
    m_objectEmu = new ObjectEmu(m_logger);
    m_peLoader = new PeLoader(m_logger);

    m_initialized = true;
    s_instance = this;
    m_logger->Trace(LOG_INFO, "MinimalKernel initialized");
    return true;
}

void MinimalKernel::Shutdown()
{
    if (!m_initialized) return;

    s_instance = nullptr;

    delete m_peLoader; m_peLoader = nullptr;
    delete m_objectEmu; m_objectEmu = nullptr;
    delete m_sectionEmu; m_sectionEmu = nullptr;
    delete m_threadManager; m_threadManager = nullptr;
    delete m_virtualState; m_virtualState = nullptr;
    delete m_cryptoEmu; m_cryptoEmu = nullptr;
    delete m_registryEmu; m_registryEmu = nullptr;
    delete m_timingEmu; m_timingEmu = nullptr;
    delete m_fileEmu; m_fileEmu = nullptr;
    delete m_memoryEmu; m_memoryEmu = nullptr;
    delete m_processEmu; m_processEmu = nullptr;

    m_initialized = false;
    m_logger->Trace(LOG_INFO, "MinimalKernel shutdown");
}

void MinimalKernel::LoadFromConfig(ConfigParser* config)
{
    if (!config) return;

    m_spoofProcess = config->GetBool("spoof", "process_info", true);
    m_spoofRegistry = config->GetBool("spoof", "registry", true);
    m_spoofFile = config->GetBool("spoof", "file", true);
    m_spoofTiming = config->GetBool("spoof", "timing", true);
    m_spoofToken = config->GetBool("spoof", "token", true);
    m_spoofThread = config->GetBool("spoof", "thread", true);
    m_cloakModule = config->GetBool("spoof", "module_cloak", true);

    if (m_processEmu) {
        m_processEmu->LoadFromConfig(config);
    }
}

void MinimalKernel::BuildVirtualProcessList()
{
    if (m_processEmu) {
        m_processEmu->BuildVirtualProcessList();
    }
}

bool MinimalKernel::HandleSyscall(uint64_t syscallNumber, uint64_t* args, uint64_t* result)
{
    switch (syscallNumber) {
        // Process syscalls
        case 0x0001:
            if (m_spoofProcess && m_processEmu)
                return m_processEmu->HandleNtQuerySystemInformation(args, result);
            return false;
        case 0x0002:
            if (m_spoofProcess && m_processEmu)
                return m_processEmu->HandleNtQueryInformationProcess(args, result);
            return false;

        // Memory syscalls
        case 0x0003:
            if (m_memoryEmu) return m_memoryEmu->HandleNtAllocateVirtualMemory(args, result);
            return false;
        case 0x0004:
            if (m_memoryEmu) return m_memoryEmu->HandleNtFreeVirtualMemory(args, result);
            return false;
        case 0x0005:
            if (m_memoryEmu) return m_memoryEmu->HandleNtProtectVirtualMemory(args, result);
            return false;
        case 0x0006:
            if (m_memoryEmu) return m_memoryEmu->HandleNtQueryVirtualMemory(args, result);
            return false;

        // File syscalls
        case 0x0007:
            if (m_spoofFile && m_fileEmu) return m_fileEmu->HandleNtCreateFile(args, result);
            return false;
        case 0x0008:
            if (m_spoofFile && m_fileEmu) return m_fileEmu->HandleNtReadFile(args, result);
            return false;
        case 0x0009:
            if (m_spoofFile && m_fileEmu) return m_fileEmu->HandleNtWriteFile(args, result);
            return false;
        case 0x000A:
            if (m_spoofFile && m_fileEmu) return m_fileEmu->HandleNtQueryInformationFile(args, result);
            return false;
        case 0x000B:
            if (m_spoofFile && m_fileEmu) return m_fileEmu->HandleNtQueryVolumeInformationFile(args, result);
            return false;
        case 0x000C:
            if (m_spoofFile && m_fileEmu) return m_fileEmu->HandleNtDeviceIoControlFile(args, result);
            return false;

        // Timing syscalls
        case 0x000D:
            if (m_spoofTiming && m_timingEmu) return m_timingEmu->HandleNtQueryPerformanceCounter(args, result);
            return false;
        case 0x000E:
            if (m_spoofTiming && m_timingEmu) return m_timingEmu->HandleNtSetTimerResolution(args, result);
            return false;
        case 0x000F:
            if (m_spoofTiming && m_timingEmu) return m_timingEmu->HandleNtQueryTimerResolution(args, result);
            return false;

        // Registry syscalls
        case 0x0010:
            if (m_spoofRegistry && m_registryEmu) return m_registryEmu->HandleNtOpenKey(args, result);
            return false;
        case 0x0011:
            if (m_spoofRegistry && m_registryEmu) return m_registryEmu->HandleNtQueryValueKey(args, result);
            return false;
        case 0x0012:
            if (m_spoofRegistry && m_registryEmu) return m_registryEmu->HandleNtEnumerateKey(args, result);
            return false;
        case 0x0013:
            if (m_spoofRegistry && m_registryEmu) return m_registryEmu->HandleNtEnumerateValueKey(args, result);
            return false;
        case 0x0014:
            if (m_spoofRegistry && m_registryEmu) return m_registryEmu->HandleNtCreateKey(args, result);
            return false;
        case 0x0015:
            if (m_spoofRegistry && m_registryEmu) return m_registryEmu->HandleNtDeleteKey(args, result);
            return false;
        case 0x0016:
            if (m_registryEmu) return m_registryEmu->HandleNtClose(args, result);
            return false;

        // Token syscalls
        case 0x0017:
            if (m_spoofToken && m_cryptoEmu) return m_cryptoEmu->HandleNtQueryInformationToken(args, result);
            return false;
        case 0x0018:
            if (m_spoofToken && m_cryptoEmu) return m_cryptoEmu->HandleNtOpenProcessToken(args, result);
            return false;
        case 0x0019:
            if (m_spoofToken && m_cryptoEmu) return m_cryptoEmu->HandleNtDuplicateToken(args, result);
            return false;

        // Process state syscalls
        case 0x001A:
            if (m_virtualState) return m_virtualState->HandleNtSetInformationProcess(args, result);
            return false;
        case 0x001B:
            if (m_virtualState) return m_virtualState->HandleNtRaiseHardError(args, result);
            return false;
        case 0x001C:
            if (m_virtualState) return m_virtualState->HandleNtShutdownSystem(args, result);
            return false;

        // Thread syscalls
        case 0x001D:
            if (m_spoofThread && m_threadManager) return m_threadManager->HandleNtCreateThread(args, result);
            return false;
        case 0x001E:
            if (m_spoofThread && m_threadManager) return m_threadManager->HandleNtOpenThread(args, result);
            return false;
        case 0x001F:
            if (m_spoofThread && m_threadManager) return m_threadManager->HandleNtSuspendThread(args, result);
            return false;
        case 0x0020:
            if (m_spoofThread && m_threadManager) return m_threadManager->HandleNtResumeThread(args, result);
            return false;
        case 0x0021:
            if (m_spoofThread && m_threadManager) return m_threadManager->HandleNtTerminateThread(args, result);
            return false;
        case 0x0022:
            if (m_spoofThread && m_threadManager) return m_threadManager->HandleNtGetContextThread(args, result);
            return false;
        case 0x0023:
            if (m_spoofThread && m_threadManager) return m_threadManager->HandleNtSetContextThread(args, result);
            return false;
        case 0x0024:
            if (m_spoofThread && m_threadManager) return m_threadManager->HandleNtQueryInformationThread(args, result);
            return false;
        case 0x0025:
            if (m_threadManager) return m_threadManager->HandleNtCreateEvent(args, result);
            return false;
        case 0x0026:
            if (m_threadManager) return m_threadManager->HandleNtSetEvent(args, result);
            return false;
        case 0x0027:
            if (m_threadManager) return m_threadManager->HandleNtWaitForSingleObject(args, result);
            return false;
        case 0x0028:
            if (m_threadManager) return m_threadManager->HandleNtWaitForMultipleObjects(args, result);
            return false;
        case 0x0029:
            if (m_threadManager) return m_threadManager->HandleNtSignalAndWaitForSingleObject(args, result);
            return false;

        case 0x002A:
            if (m_spoofProcess && m_processEmu) return m_processEmu->HandleNtOpenProcess(args, result);
            return false;

        case 0x002B:
            if (m_objectEmu) return m_objectEmu->HandleNtQueryObject(args, result);
            return false;

        case 0x002C:
            if (m_spoofFile && m_fileEmu) return m_fileEmu->HandleNtQueryAttributesFile(args, result);
            return false;
        case 0x002D:
            if (m_spoofFile && m_fileEmu) return m_fileEmu->HandleNtOpenFile(args, result);
            return false;
        case 0x002E:
            if (m_spoofFile && m_fileEmu) return m_fileEmu->HandleNtDeleteFile(args, result);
            return false;
        case 0x002F:
            if (m_spoofFile && m_fileEmu) return m_fileEmu->HandleNtQueryDirectoryFile(args, result);
            return false;
        case 0x0030:
            if (m_spoofFile && m_fileEmu) return m_fileEmu->HandleNtNotifyChangeDirectoryFile(args, result);
            return false;

        case 0x0031:
            if (m_spoofRegistry && m_registryEmu) return m_registryEmu->HandleNtOpenKey(args, result);
            return false;



        case 0x0035:
            if (m_sectionEmu) return m_sectionEmu->HandleNtOpenSection(args, result);
            return false;
        case 0x0036:
            if (m_sectionEmu) return m_sectionEmu->HandleNtCreateSection(args, result);
            return false;
        case 0x0037:
            if (m_sectionEmu) return m_sectionEmu->HandleNtMapViewOfSection(args, result);
            return false;
        case 0x0038:
            if (m_sectionEmu) return m_sectionEmu->HandleNtUnmapViewOfSection(args, result);
            return false;

        default:
            m_logger->Trace(LOG_EMU, "MinimalKernel: unhandled syscall 0x%llX", syscallNumber);
            return false;
    }
}

bool MinimalKernel::DispatchThunk(uint64_t syscallNumber, uint64_t* args, uint64_t* result)
{
    if (!s_instance) return false;
    return s_instance->HandleSyscall(syscallNumber, args, result);
}
