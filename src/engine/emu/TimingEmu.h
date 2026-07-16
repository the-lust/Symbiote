#pragma once
#include <cstdint>
#include <windows.h>
#include "Logger.h"

class TimingEmu {
public:
    explicit TimingEmu(Logger* logger);

    void SetSyntheticTscSource(uint64_t* tscPtr);

    bool HandleNtQueryPerformanceCounter(uint64_t* args, uint64_t* result);
    bool HandleNtSetTimerResolution(uint64_t* args, uint64_t* result);
    bool HandleNtQueryTimerResolution(uint64_t* args, uint64_t* result);
    bool HandleGetTickCount(uint64_t* args, uint64_t* result);
    bool HandleGetSystemTime(uint64_t* args, uint64_t* result);
    bool HandleGetSystemTimeAdjustment(uint64_t* args, uint64_t* result);

    uint64_t GetSyntheticQpc() const;
    uint64_t GetSyntheticTickCount() const;

private:
    Logger* m_logger;
    uint64_t* m_syntheticTscBase;
    uint64_t m_syntheticTscFreq;
    uint64_t m_qpcBase;
    uint64_t m_tickBase;
    uint64_t m_timeBase;
    bool m_initialized;
};
