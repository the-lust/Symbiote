#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include <string>
#include "Logger.h"
#include "KuserLayout.h"

class ConfigParser;
class Partition;
class RdtscHandler;

class KuserSync {
public:
    KuserSync(Logger* logger, Partition* partition);
    ~KuserSync();

    bool Initialize();
    bool Initialize(ConfigParser* config);
    bool StartSyncThread();
    void StopSyncThread();

    void SyncTimeFields();
    void* GetSpoofedKuser() { return m_spoofedKuser; }

    // Re-assert the EPT mapping of the spoof page at KUSER GPA. Required
    // AFTER the guest page tables are built: GuestPageTable::Build skips the
    // KUSER page itself, but this is belt-and-braces so a stale/replaced
    // mapping (e.g. a future page-table builder change) can never leave the
    // guest reading the host's real KUSER page.
    bool ReapplyGpaMapping();

    void SetRdtscHandler(RdtscHandler* h) { m_rdtscHandler = h; }

    // Config-driven identity fields (TIP values; zero-rule for everything else)
    void SetNtMajorVersion(uint8_t v) { m_ntMajorVersion = v; }
    void SetNtMinorVersion(uint8_t v) { m_ntMinorVersion = v; }
    void SetBuildNumber(uint16_t v) { m_buildNumber = v; }
    void SetNumberOfPhysicalPages(uint64_t v) { m_numberOfPhysicalPages = v; }
    void SetSuiteMask(uint32_t v) { m_suiteMask = v; }
    void SetProductTypeIsValid(uint8_t v) { m_productTypeIsValid = v; }
    void SetActiveProcessorCount(uint32_t v) { m_activeProcessorCount = v; }
    void SetNativeProcessorArchitecture(uint16_t v) { m_nativeProcessorArchitecture = v; }

private:
    static DWORD WINAPI SyncThreadProc(LPVOID lpParam);

    Logger* m_logger;
    Partition* m_partition;
    RdtscHandler* m_rdtscHandler;
    HANDLE m_syncThread;
    HANDLE m_stopEvent;
    bool m_running;
    bool m_gpaMapped;
    uint32_t m_syncIterations;

    void* m_spoofedKuser;

    // Guest page tables are identity-mapped (guest VA -> GPA = VA), so the
    // KUSER page's GPA IS its VA — the spoof buffer is mapped at KUSER_VA
    // and serves any process whose PTEs point KUSER -> identity GPA.
    // (KUSER_VA / KUSER_PAGE_SIZE are macros from KuserLayout.h.)

    void LoadConfig(ConfigParser* config);
    void ApplyStaticSpoofs();
    void SetKSystemTime(KSYSTEM_TIME_X64* dst, uint64_t value);

    int64_t m_systemTimeOffset;
    int64_t m_interruptTimeOffset;
    int32_t m_utcBias;

    uint32_t m_ntMajorVersion = 10;
    uint32_t m_ntMinorVersion = 0;
    uint32_t m_buildNumber = 19045;
    uint32_t m_productType = 1;
    uint8_t  m_productTypeIsValid = 1;
    uint16_t m_nativeProcessorArchitecture = 9;
    uint32_t m_suiteMask = 0x0110;
    uint32_t m_activeProcessorCount = 4;
    uint32_t m_activeGroupCount = 1;
    uint64_t m_numberOfPhysicalPages = 0x1FA054; // LUST donor: 8,489,091,072 B
    uint64_t m_qpcFrequency = 10000000;
    uint64_t m_tscFrequency = 1995375200;
    uint64_t m_systemTimeAnchor = 0;             // 0 = wall clock at engine start
    uint8_t  m_mitigationPolicies = 0x0A;        // matches real Win10/Win11 (NX=2, SEH=2)
    uint16_t m_cyclesPerYield = 9;               // real-validated default
    uint32_t m_sharedDataFlags = 0;              // zero-rule (unverifiable per donor)
    uint8_t  m_processorFeatures[64] = { 0 };    // zero-rule until a donor dump exists
};