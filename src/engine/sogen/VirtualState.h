#pragma once
#include <cstdint>
#include <windows.h>
#include "Logger.h"

class VirtualState {
public:
    explicit VirtualState(Logger* logger);

    bool HandleNtSetInformationProcess(uint64_t* args, uint64_t* result);
    bool HandleNtRaiseHardError(uint64_t* args, uint64_t* result);
    bool HandleNtShutdownSystem(uint64_t* args, uint64_t* result);

private:
    Logger* m_logger;
};
