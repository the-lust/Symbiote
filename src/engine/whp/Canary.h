#pragma once
#include <windows.h>
#include "Logger.h"

class CaptureLogger;

class Canary {
public:
    explicit Canary(Logger* logger);
    ~Canary();

    bool Initialize();
    void Shutdown();
    void SetCaptureLogger(CaptureLogger* cap) { m_captureLogger = cap; }

    // Get canary page address for sharing with target
    void* GetCanaryPage() const { return m_canaryPage; }

    LONG OnException(EXCEPTION_POINTERS* ep);

    // Canary handshake data layout (at offset 0 of canary page)
    struct CanaryHandshake {
        volatile uint32_t magic;
        volatile uint32_t flags;
        volatile uint64_t handshakeGpa;
        volatile uint64_t targetPid;
        uint8_t reserved[4080];
    };

    CanaryHandshake* GetHandshake() const {
        return (CanaryHandshake*)m_canaryPage;
    }

private:
    Logger* m_logger;
    CaptureLogger* m_captureLogger;
    void* m_canaryPage;
    void* m_vehHandle;
    bool m_initialized;

    static Canary* s_instance;
    static LONG CALLBACK VectoredHandler(EXCEPTION_POINTERS* ep);
};

extern Canary* g_canary;