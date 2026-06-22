#include "SyscallDispatcher.h"
#include "ProcessEmu.h"
#include "MemoryEmu.h"
#include "FileEmu.h"
#include "TimingEmu.h"
#include "RegistryEmu.h"
#include "CryptoEmu.h"
#include "VirtualState.h"
#include "ThreadManager.h"
#include "SectionEmu.h"
#include "ObjectEmu.h"

SyscallDispatcher::SyscallDispatcher(Logger* logger)
    : m_logger(logger),
      m_processEmu(nullptr), m_memoryEmu(nullptr), m_fileEmu(nullptr),
      m_timingEmu(nullptr), m_registryEmu(nullptr), m_cryptoEmu(nullptr),
      m_virtualState(nullptr), m_threadManager(nullptr),
      m_sectionEmu(nullptr), m_objectEmu(nullptr)
{
}

SyscallDispatcher::~SyscallDispatcher()
{
}

void SyscallDispatcher::RegisterHandlers(ProcessEmu* proc, MemoryEmu* mem, FileEmu* file,
                                          TimingEmu* timing, RegistryEmu* reg, CryptoEmu* crypto,
                                          VirtualState* vs, ThreadManager* tm)
{
    m_processEmu = proc;
    m_memoryEmu = mem;
    m_fileEmu = file;
    m_timingEmu = timing;
    m_registryEmu = reg;
    m_cryptoEmu = crypto;
    m_virtualState = vs;
    m_threadManager = tm;
}

void SyscallDispatcher::RegisterExtendedHandlers(SectionEmu* sec, ObjectEmu* obj)
{
    m_sectionEmu = sec;
    m_objectEmu = obj;
}

bool SyscallDispatcher::Dispatch(uint64_t syscallNumber, uint64_t* args, uint64_t* result)
{
    switch (syscallNumber) {
        // Process syscalls
        case SYSCALL_NT_QUERY_SYSTEM_INFORMATION:
            if (m_processEmu) return m_processEmu->HandleNtQuerySystemInformation(args, result);
            break;
        case SYSCALL_NT_QUERY_INFORMATION_PROCESS:
            if (m_processEmu) return m_processEmu->HandleNtQueryInformationProcess(args, result);
            break;

        // Memory syscalls
        case SYSCALL_NT_ALLOCATE_VIRTUAL_MEMORY:
            if (m_memoryEmu) return m_memoryEmu->HandleNtAllocateVirtualMemory(args, result);
            break;
        case SYSCALL_NT_FREE_VIRTUAL_MEMORY:
            if (m_memoryEmu) return m_memoryEmu->HandleNtFreeVirtualMemory(args, result);
            break;
        case SYSCALL_NT_PROTECT_VIRTUAL_MEMORY:
            if (m_memoryEmu) return m_memoryEmu->HandleNtProtectVirtualMemory(args, result);
            break;
        case SYSCALL_NT_QUERY_VIRTUAL_MEMORY:
            if (m_memoryEmu) return m_memoryEmu->HandleNtQueryVirtualMemory(args, result);
            break;

        // File syscalls
        case SYSCALL_NT_CREATE_FILE:
            if (m_fileEmu) return m_fileEmu->HandleNtCreateFile(args, result);
            break;
        case SYSCALL_NT_READ_FILE:
            if (m_fileEmu) return m_fileEmu->HandleNtReadFile(args, result);
            break;
        case SYSCALL_NT_WRITE_FILE:
            if (m_fileEmu) return m_fileEmu->HandleNtWriteFile(args, result);
            break;
        case SYSCALL_NT_QUERY_INFORMATION_FILE:
            if (m_fileEmu) return m_fileEmu->HandleNtQueryInformationFile(args, result);
            break;
        case SYSCALL_NT_QUERY_VOLUME_INFORMATION_FILE:
            if (m_fileEmu) return m_fileEmu->HandleNtQueryVolumeInformationFile(args, result);
            break;
        case SYSCALL_NT_DEVICE_IO_CONTROL_FILE:
            if (m_fileEmu) return m_fileEmu->HandleNtDeviceIoControlFile(args, result);
            break;

        // Timing syscalls
        case SYSCALL_NT_QUERY_PERFORMANCE_COUNTER:
            if (m_timingEmu) return m_timingEmu->HandleNtQueryPerformanceCounter(args, result);
            break;
        case SYSCALL_NT_SET_TIMER_RESOLUTION:
            if (m_timingEmu) return m_timingEmu->HandleNtSetTimerResolution(args, result);
            break;
        case SYSCALL_NT_QUERY_TIMER_RESOLUTION:
            if (m_timingEmu) return m_timingEmu->HandleNtQueryTimerResolution(args, result);
            break;

        // Registry syscalls
        case SYSCALL_NT_OPEN_KEY:
            if (m_registryEmu) return m_registryEmu->HandleNtOpenKey(args, result);
            break;
        case SYSCALL_NT_QUERY_VALUE_KEY:
            if (m_registryEmu) return m_registryEmu->HandleNtQueryValueKey(args, result);
            break;
        case SYSCALL_NT_ENUMERATE_KEY:
            if (m_registryEmu) return m_registryEmu->HandleNtEnumerateKey(args, result);
            break;
        case SYSCALL_NT_ENUMERATE_VALUE_KEY:
            if (m_registryEmu) return m_registryEmu->HandleNtEnumerateValueKey(args, result);
            break;
        case SYSCALL_NT_CREATE_KEY:
            if (m_registryEmu) return m_registryEmu->HandleNtCreateKey(args, result);
            break;
        case SYSCALL_NT_DELETE_KEY:
            if (m_registryEmu) return m_registryEmu->HandleNtDeleteKey(args, result);
            break;
        case SYSCALL_NT_CLOSE:
            if (m_registryEmu) return m_registryEmu->HandleNtClose(args, result);
            break;

        // Token syscalls
        case SYSCALL_NT_QUERY_INFORMATION_TOKEN:
            if (m_cryptoEmu) return m_cryptoEmu->HandleNtQueryInformationToken(args, result);
            break;
        case SYSCALL_NT_OPEN_PROCESS_TOKEN:
            if (m_cryptoEmu) return m_cryptoEmu->HandleNtOpenProcessToken(args, result);
            break;
        case SYSCALL_NT_DUPLICATE_TOKEN:
            if (m_cryptoEmu) return m_cryptoEmu->HandleNtDuplicateToken(args, result);
            break;

        // State syscalls
        case SYSCALL_NT_SET_INFORMATION_PROCESS:
            if (m_virtualState) return m_virtualState->HandleNtSetInformationProcess(args, result);
            break;
        case SYSCALL_NT_RAISE_HARD_ERROR:
            if (m_virtualState) return m_virtualState->HandleNtRaiseHardError(args, result);
            break;
        case SYSCALL_NT_SHUTDOWN_SYSTEM:
            if (m_virtualState) return m_virtualState->HandleNtShutdownSystem(args, result);
            break;

        // Thread syscalls
        case SYSCALL_NT_CREATE_THREAD:
            if (m_threadManager) return m_threadManager->HandleNtCreateThread(args, result);
            break;
        case SYSCALL_NT_OPEN_THREAD:
            if (m_threadManager) return m_threadManager->HandleNtOpenThread(args, result);
            break;
        case SYSCALL_NT_SUSPEND_THREAD:
            if (m_threadManager) return m_threadManager->HandleNtSuspendThread(args, result);
            break;
        case SYSCALL_NT_RESUME_THREAD:
            if (m_threadManager) return m_threadManager->HandleNtResumeThread(args, result);
            break;
        case SYSCALL_NT_TERMINATE_THREAD:
            if (m_threadManager) return m_threadManager->HandleNtTerminateThread(args, result);
            break;
        case SYSCALL_NT_GET_CONTEXT_THREAD:
            if (m_threadManager) return m_threadManager->HandleNtGetContextThread(args, result);
            break;
        case SYSCALL_NT_SET_CONTEXT_THREAD:
            if (m_threadManager) return m_threadManager->HandleNtSetContextThread(args, result);
            break;
        case SYSCALL_NT_QUERY_INFORMATION_THREAD:
            if (m_threadManager) return m_threadManager->HandleNtQueryInformationThread(args, result);
            break;
        case SYSCALL_NT_CREATE_EVENT:
            if (m_threadManager) return m_threadManager->HandleNtCreateEvent(args, result);
            break;
        case SYSCALL_NT_SET_EVENT:
            if (m_threadManager) return m_threadManager->HandleNtSetEvent(args, result);
            break;
        case SYSCALL_NT_WAIT_FOR_SINGLE_OBJECT:
            if (m_threadManager) return m_threadManager->HandleNtWaitForSingleObject(args, result);
            break;
        case SYSCALL_NT_WAIT_FOR_MULTIPLE_OBJECTS:
            if (m_threadManager) return m_threadManager->HandleNtWaitForMultipleObjects(args, result);
            break;
        case SYSCALL_NT_SIGNAL_AND_WAIT_FOR_SINGLE:
            if (m_threadManager) return m_threadManager->HandleNtSignalAndWaitForSingleObject(args, result);
            break;

        // Process
        case SYSCALL_NT_OPEN_PROCESS:
            if (m_processEmu) return m_processEmu->HandleNtOpenProcess(args, result);
            break;

        // Object
        case SYSCALL_NT_QUERY_OBJECT:
            if (m_objectEmu) return m_objectEmu->HandleNtQueryObject(args, result);
            break;

        // Extended file syscalls
        case SYSCALL_NT_QUERY_ATTRIBUTES_FILE:
            if (m_fileEmu) return m_fileEmu->HandleNtQueryAttributesFile(args, result);
            break;
        case SYSCALL_NT_OPEN_FILE:
            if (m_fileEmu) return m_fileEmu->HandleNtOpenFile(args, result);
            break;
        case SYSCALL_NT_DELETE_FILE:
            if (m_fileEmu) return m_fileEmu->HandleNtDeleteFile(args, result);
            break;
        case SYSCALL_NT_QUERY_DIRECTORY_FILE:
            if (m_fileEmu) return m_fileEmu->HandleNtQueryDirectoryFile(args, result);
            break;
        case SYSCALL_NT_NOTIFY_CHANGE_DIRECTORY_FILE:
            if (m_fileEmu) return m_fileEmu->HandleNtNotifyChangeDirectoryFile(args, result);
            break;

        // Section
        case SYSCALL_NT_CREATE_SECTION:
            if (m_sectionEmu) return m_sectionEmu->HandleNtCreateSection(args, result);
            break;
        case SYSCALL_NT_OPEN_SECTION:
            if (m_sectionEmu) return m_sectionEmu->HandleNtOpenSection(args, result);
            break;
        case SYSCALL_NT_MAP_VIEW_OF_SECTION:
            if (m_sectionEmu) return m_sectionEmu->HandleNtMapViewOfSection(args, result);
            break;
        case SYSCALL_NT_UNMAP_VIEW_OF_SECTION:
            if (m_sectionEmu) return m_sectionEmu->HandleNtUnmapViewOfSection(args, result);
            break;

        default:
            m_logger->Trace(LOG_SOGEN, "Unhandled syscall 0x%llX", syscallNumber);
            return false;
    }

    return false;
}
