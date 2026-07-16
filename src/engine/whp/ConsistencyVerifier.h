#pragma once
#include <windows.h>
#include <iphlpapi.h>
#include <cstdint>
#include "Logger.h"

#pragma comment(lib, "iphlpapi.lib")

class ConsistencyVerifier {
public:
    explicit ConsistencyVerifier(Logger* logger);
    ~ConsistencyVerifier();

    bool Initialize();
    void Shutdown();

    bool VerifyAll();

    bool VerifyCpuCount();
    bool VerifyCacheSizes();
    bool VerifyMemorySize();
    bool VerifyTscFrequency();
    bool VerifyBrandString();
    bool VerifyManufacturer();
    bool VerifyBiosVersion();
    bool VerifyTimingConsistency();

    // Optional extended checks
    bool VerifyChassisInfo();
    bool VerifyDiskInfo();
    bool VerifyNetworkInfo();
    bool VerifySensorData();

    const char* GetSummary();

private:
    Logger* m_logger;
    bool m_initialized;
    uint32_t m_passedChecks;
    uint32_t m_failedChecks;
    char m_summary[128];
};
