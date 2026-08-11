#pragma once
#include <windows.h>
#include <iphlpapi.h>
#include <cstdint>
#include "Logger.h"
#include "KuserLayout.h"

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
    bool VerifyChassisInfo();
    bool VerifyDiskInfo();
    bool VerifyNetworkInfo();
    bool VerifyKuserSelfConsistency();

    // When the engine's KUSER spoof is live, KUSER-derived checks validate
    // the SPOOFED page (TIP self-coherence, fail-loud on mismatch); the host
    // KUSER page is used only as environment reference. Set before VerifyAll.
    void SetSpoofedKuserSource(const void* spoofedKuser) { m_spoofedKuserSource = spoofedKuser; }

    const char* GetSummary();

private:
    const KUSER_SHARED_DATA_X64* KuserView() const;

    Logger* m_logger;
    bool m_initialized;
    uint32_t m_passedChecks;
    uint32_t m_failedChecks;
    const void* m_spoofedKuserSource;
    char m_summary[128];
};
