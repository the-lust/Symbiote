#include "SyscallBridge.h"

static SyscallHandler* g_syscallHandler = nullptr;

void SetSyscallHandler(SyscallHandler* handler)
{
    g_syscallHandler = handler;
}

#pragma comment(linker, "/EXPORT:RouteSyscall=RouteSyscall")

bool __stdcall RouteSyscall(uint64_t syscallNumber, uint64_t* args, uint64_t* result)
{
    if (!g_syscallHandler) return false;
    return g_syscallHandler(syscallNumber, args, result);
}
