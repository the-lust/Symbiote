#pragma once
#include <windows.h>
#include <unordered_map>
#include "Logger.h"

class CpuProfile;
class TimingProfile;

class CodePatcher {
public:
    CodePatcher(Logger* logger, CpuProfile* cpuProfile, TimingProfile* timingProfile);
    ~CodePatcher();

    bool Initialize();
    void Shutdown();
    bool IsPatched() const { return m_initialized && !m_patches.empty(); }

private:
    struct PatchEntry {
        uint8_t originalByte;
        int instrLength;
        int type;
    };

    using PatchMap = std::unordered_map<void*, PatchEntry>;

    Logger* m_logger;
    CpuProfile* m_cpuProfile;
    TimingProfile* m_timingProfile;
    PatchMap m_patches;
    void* m_vehHandle;
    CRITICAL_SECTION m_cs;
    bool m_initialized;
    uint64_t m_lastSpoofedTsc;
    uint64_t m_cpuidTimingBase;
    bool m_cpuidTimingPending;

    bool ScanModule(const wchar_t* moduleName, uint8_t* baseAddr, SIZE_T moduleSize);
    bool ScanSection(uint8_t* sectionStart, SIZE_T sectionSize);

    static CodePatcher* s_instance;
    static LONG CALLBACK VectoredHandler(EXCEPTION_POINTERS* ep);
    LONG OnException(EXCEPTION_POINTERS* ep);
};
