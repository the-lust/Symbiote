#include <cstdio>
#include <cassert>
#include "sogen/SyscallDispatcher.h"
#include "sogen/SyscallNames.h"
#include "Logger.h"

void test_syscall_dispatch()
{
    Logger logger;
    logger.Init();
    logger.SetVerbose(false);

    SyscallDispatcher dispatcher(&logger);

    // Test syscall name lookup
    const char* name = GetSyscallName(0x0036);
    assert(name != nullptr);
    printf("  Syscall 0x0036: %s\n", name);

    name = GetSyscallName(0x0019);
    assert(name != nullptr);
    printf("  Syscall 0x0019: %s\n", name);

    // Test unknown syscall
    name = GetSyscallName(0xFFFF);
    printf("  Syscall 0xFFFF: %s\n", name);

    // Test dispatch (unregistered = no handler, should return false)
    uint64_t args[6] = {0};
    uint64_t result = 0;
    bool handled = dispatcher.Dispatch(0xFFFF, args, &result);
    assert(!handled); // No handler registered

    printf("  Dispatch of unknown syscall returns false (expected)\n");
    printf("  Syscall table has %llu entries\n", GetSyscallCount());
}
