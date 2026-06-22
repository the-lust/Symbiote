#pragma once
#include <cstdint>
#include <windows.h>
#include "Logger.h"

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

class SyscallDispatcher {
public:
    explicit SyscallDispatcher(Logger* logger);
    ~SyscallDispatcher();

    void RegisterHandlers(ProcessEmu* proc, MemoryEmu* mem, FileEmu* file,
                          TimingEmu* timing, RegistryEmu* reg, CryptoEmu* crypto,
                          VirtualState* vs, ThreadManager* tm);
    void RegisterExtendedHandlers(SectionEmu* sec, ObjectEmu* obj);

    bool Dispatch(uint64_t syscallNumber, uint64_t* args, uint64_t* result);

private:
    Logger* m_logger;
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

    // Syscall number constants (NT x64)
    static const uint64_t SYSCALL_NT_QUERY_SYSTEM_INFORMATION        = 0x0001;
    static const uint64_t SYSCALL_NT_QUERY_INFORMATION_PROCESS       = 0x0002;
    static const uint64_t SYSCALL_NT_ALLOCATE_VIRTUAL_MEMORY         = 0x0003;
    static const uint64_t SYSCALL_NT_FREE_VIRTUAL_MEMORY             = 0x0004;
    static const uint64_t SYSCALL_NT_PROTECT_VIRTUAL_MEMORY          = 0x0005;
    static const uint64_t SYSCALL_NT_QUERY_VIRTUAL_MEMORY            = 0x0006;
    static const uint64_t SYSCALL_NT_CREATE_FILE                     = 0x0007;
    static const uint64_t SYSCALL_NT_READ_FILE                       = 0x0008;
    static const uint64_t SYSCALL_NT_WRITE_FILE                      = 0x0009;
    static const uint64_t SYSCALL_NT_QUERY_INFORMATION_FILE          = 0x000A;
    static const uint64_t SYSCALL_NT_QUERY_VOLUME_INFORMATION_FILE   = 0x000B;
    static const uint64_t SYSCALL_NT_DEVICE_IO_CONTROL_FILE          = 0x000C;
    static const uint64_t SYSCALL_NT_QUERY_PERFORMANCE_COUNTER       = 0x000D;
    static const uint64_t SYSCALL_NT_SET_TIMER_RESOLUTION            = 0x000E;
    static const uint64_t SYSCALL_NT_QUERY_TIMER_RESOLUTION          = 0x000F;
    static const uint64_t SYSCALL_NT_OPEN_KEY                        = 0x0010;
    static const uint64_t SYSCALL_NT_QUERY_VALUE_KEY                 = 0x0011;
    static const uint64_t SYSCALL_NT_ENUMERATE_KEY                   = 0x0012;
    static const uint64_t SYSCALL_NT_ENUMERATE_VALUE_KEY             = 0x0013;
    static const uint64_t SYSCALL_NT_CREATE_KEY                      = 0x0014;
    static const uint64_t SYSCALL_NT_DELETE_KEY                      = 0x0015;
    static const uint64_t SYSCALL_NT_CLOSE                           = 0x0016;
    static const uint64_t SYSCALL_NT_QUERY_INFORMATION_TOKEN         = 0x0017;
    static const uint64_t SYSCALL_NT_OPEN_PROCESS_TOKEN              = 0x0018;
    static const uint64_t SYSCALL_NT_DUPLICATE_TOKEN                 = 0x0019;
    static const uint64_t SYSCALL_NT_SET_INFORMATION_PROCESS         = 0x001A;
    static const uint64_t SYSCALL_NT_RAISE_HARD_ERROR                = 0x001B;
    static const uint64_t SYSCALL_NT_SHUTDOWN_SYSTEM                 = 0x001C;
    static const uint64_t SYSCALL_NT_CREATE_THREAD                   = 0x001D;
    static const uint64_t SYSCALL_NT_OPEN_THREAD                     = 0x001E;
    static const uint64_t SYSCALL_NT_SUSPEND_THREAD                  = 0x001F;
    static const uint64_t SYSCALL_NT_RESUME_THREAD                   = 0x0020;
    static const uint64_t SYSCALL_NT_TERMINATE_THREAD                = 0x0021;
    static const uint64_t SYSCALL_NT_GET_CONTEXT_THREAD              = 0x0022;
    static const uint64_t SYSCALL_NT_SET_CONTEXT_THREAD              = 0x0023;
    static const uint64_t SYSCALL_NT_QUERY_INFORMATION_THREAD        = 0x0024;
    static const uint64_t SYSCALL_NT_CREATE_EVENT                    = 0x0025;
    static const uint64_t SYSCALL_NT_SET_EVENT                       = 0x0026;
    static const uint64_t SYSCALL_NT_WAIT_FOR_SINGLE_OBJECT          = 0x0027;
    static const uint64_t SYSCALL_NT_WAIT_FOR_MULTIPLE_OBJECTS       = 0x0028;
    static const uint64_t SYSCALL_NT_SIGNAL_AND_WAIT_FOR_SINGLE      = 0x0029;
    static const uint64_t SYSCALL_NT_OPEN_PROCESS                    = 0x002A;
    static const uint64_t SYSCALL_NT_QUERY_OBJECT                    = 0x002B;
    static const uint64_t SYSCALL_NT_QUERY_ATTRIBUTES_FILE           = 0x002C;
    static const uint64_t SYSCALL_NT_OPEN_FILE                       = 0x002D;
    static const uint64_t SYSCALL_NT_DELETE_FILE                     = 0x002E;
    static const uint64_t SYSCALL_NT_QUERY_DIRECTORY_FILE            = 0x002F;
    static const uint64_t SYSCALL_NT_NOTIFY_CHANGE_DIRECTORY_FILE    = 0x0030;
    static const uint64_t SYSCALL_NT_OPEN_KEY_EX                     = 0x0031;
    static const uint64_t SYSCALL_NT_QUERY_MUTANT                    = 0x0032;
    static const uint64_t SYSCALL_NT_CREATE_MUTANT                   = 0x0033;
    static const uint64_t SYSCALL_NT_OPEN_MUTANT                     = 0x0034;
    static const uint64_t SYSCALL_NT_OPEN_SECTION                    = 0x0035;
    static const uint64_t SYSCALL_NT_CREATE_SECTION                  = 0x0036;
    static const uint64_t SYSCALL_NT_MAP_VIEW_OF_SECTION             = 0x0037;
    static const uint64_t SYSCALL_NT_UNMAP_VIEW_OF_SECTION           = 0x0038;
};
