#pragma once
#include <cstdint>
#include <windows.h>
#include "Logger.h"

class MemoryEmu {
public:
    explicit MemoryEmu(Logger* logger);

    bool HandleNtAllocateVirtualMemory(uint64_t* args, uint64_t* result);
    bool HandleNtFreeVirtualMemory(uint64_t* args, uint64_t* result);
    bool HandleNtProtectVirtualMemory(uint64_t* args, uint64_t* result);
    bool HandleNtQueryVirtualMemory(uint64_t* args, uint64_t* result);

private:
    Logger* m_logger;
    enum State { UNINITIALIZED, INITIALIZED };
    State m_state;
};
