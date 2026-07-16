#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include <string>
#include "Logger.h"

class ConfigParser;
class Partition;

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
    HANDLE m_syncThread;
    HANDLE m_stopEvent;
    bool m_running;

    void* m_spoofedKuser;
    static const uint64_t KUSER_GPA = 0x7FFE0000;
    static const uint32_t KUSER_PAGE_SIZE = 0x1000;

    void ApplyStaticSpoofs();

    int64_t m_systemTimeOffset;
    int64_t m_interruptTimeOffset;
    int32_t m_utcBias;

    uint8_t  m_ntMajorVersion = 0x0A;
    uint8_t  m_ntMinorVersion = 0x00;
    uint16_t m_buildNumber = 19045;
    uint64_t m_numberOfPhysicalPages = 0x7FF7E;
    uint32_t m_suiteMask = 0x0110;
    uint8_t  m_productTypeIsValid = 0x01;
    uint32_t m_activeProcessorCount = 4;
    uint16_t m_nativeProcessorArchitecture = 0x0009;
};
