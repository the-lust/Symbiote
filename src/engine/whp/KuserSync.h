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
};
