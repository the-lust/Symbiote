#pragma once
#include <cstdint>
#include <windows.h>
#include "Logger.h"
#include "profile/TimingProfile.h"

class TimingEmu {
public:
    explicit TimingEmu(Logger* logger, class TimingProfile* profile = nullptr);

    bool HandleNtQueryPerformanceCounter(uint64_t* args, uint64_t* result);
    bool HandleNtSetTimerResolution(uint64_t* args, uint64_t* result);
    bool HandleNtQueryTimerResolution(uint64_t* args, uint64_t* result);
    bool HandleGetTickCount(uint64_t* args, uint64_t* result);
    bool HandleGetSystemTime(uint64_t* args, uint64_t* result);

    uint64_t GetSpoofedQpc() const;

private:
    Logger* m_logger;
    class TimingProfile* m_profile;
    uint64_t m_qpcOffset;
};
