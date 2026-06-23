#pragma once
#include <cstdint>
#include <windows.h>
#include "Logger.h"

class TimingEmu {
public:
    explicit TimingEmu(Logger* logger);

    bool HandleNtQueryPerformanceCounter(uint64_t* args, uint64_t* result);
    bool HandleNtSetTimerResolution(uint64_t* args, uint64_t* result);
    bool HandleNtQueryTimerResolution(uint64_t* args, uint64_t* result);
    bool HandleGetTickCount(uint64_t* args, uint64_t* result);
    bool HandleGetSystemTime(uint64_t* args, uint64_t* result);

    uint64_t GetSpoofedQpc() const;

private:
    Logger* m_logger;
    uint64_t m_qpcOffset;
};
