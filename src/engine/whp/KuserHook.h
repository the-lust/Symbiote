#pragma once
#include <windows.h>
#include "Logger.h"

class KuserHook {
public:
    explicit KuserHook(Logger* logger);
    ~KuserHook();

    bool Initialize();
    void Shutdown();
    bool IsActive() const { return m_active; }

    void SyncTimeFields();
    void* GetSpoofedKuser() const { return m_spoofedKuser; }

private:
    static DWORD WINAPI SyncThreadProc(LPVOID lpParam);

    Logger* m_logger;
    void* m_spoofedKuser;
    void* m_sharedView;
    HANDLE m_sharedMap;
    void* m_vehHandle;
    HANDLE m_syncThread;
    HANDLE m_stopEvent;
    bool m_active;
    bool m_running;

    bool TryProtectKuserPage();
    void CopyStaticSpoofs();
    void ApplyStableSpoofs();

    static KuserHook* s_instance;
    static LONG CALLBACK VectoredHandler(EXCEPTION_POINTERS* ep);
    LONG OnException(EXCEPTION_POINTERS* ep);

    static const uint64_t KUSER_VA = 0x7FFE0000;
    static const uint32_t KUSER_PAGE_SIZE = 0x1000;
};
