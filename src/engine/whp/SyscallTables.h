#pragma once
#include <cstdint>

class SyscallTables {
public:
    static uint32_t DetectBuildNumber();
    static uint32_t Lookup(const char* name, uint32_t buildNumber);
    static bool CrossCheck(const char* name, uint32_t detectedSsn, uint32_t buildNumber);
    static bool HasTable(uint32_t buildNumber);
    static uint32_t GetClosestBuild(uint32_t actualBuild);
};
