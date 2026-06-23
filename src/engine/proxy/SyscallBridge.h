#pragma once
#include <cstdint>

using SyscallHandler = bool(uint64_t syscallNumber, uint64_t* args, uint64_t* result);
void SetSyscallHandler(SyscallHandler* handler);

extern "C" bool __stdcall RouteSyscall(uint64_t syscallNumber, uint64_t* args, uint64_t* result);
