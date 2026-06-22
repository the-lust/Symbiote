#pragma once
#include <cstdint>
#include <windows.h>
#include "Logger.h"
#include "SyscallDispatcher.h"

class SoGenEmulator {
public:
    SoGenEmulator(Logger* logger, SyscallDispatcher* dispatcher);
    ~SoGenEmulator();

    bool EmulateSyscall(uint64_t syscallNumber, uint64_t* args, uint64_t* result);

private:
    Logger* m_logger;
    SyscallDispatcher* m_dispatcher;
};
