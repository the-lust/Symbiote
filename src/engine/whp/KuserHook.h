#pragma once
#include <windows.h>
#include "Logger.h"
#include "KuserLayout.h"

// M-B fallback (VEH overlay) used when WHP/EPT is unavailable (IAT-only mode).
// The guest's reads of KUSER_VA are served from a generated spoofed page in
// this process; the real KUSER page is never read and never copied (zero-rule).
// Primary path is KuserSync (EPT split) — this exists only as a fallback.
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
    void BuildSpoofedPage();

    static KuserHook* s_instance;
    static LONG CALLBACK VectoredHandler(EXCEPTION_POINTERS* ep);
    LONG OnException(EXCEPTION_POINTERS* ep);

    static const uint32_t KUSER_PAGE_SIZE_ = KUSER_PAGE_SIZE;
};