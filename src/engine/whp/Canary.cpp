#include "Canary.h"
#include "capture/CaptureLogger.h"
#include <cstring>

Canary* g_canary = nullptr;
Canary* Canary::s_instance = nullptr;

Canary::Canary(Logger* logger)
    : m_logger(logger), m_captureLogger(nullptr), m_canaryPage(nullptr),
      m_vehHandle(nullptr), m_initialized(false)
{
}

Canary::~Canary()
{
    Shutdown();
}

bool Canary::Initialize()
{
    if (m_initialized) return true;

    // Allocate a canary page (handshake + scanner trap)
    m_canaryPage = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!m_canaryPage) {
        m_logger->Trace(LOG_WARNING, "Canary: VirtualAlloc failed (%u)", GetLastError());
        return false;
    }

    // Zero the page
    memset(m_canaryPage, 0, 0x1000);

    // Write canary handshake header
    CanaryHandshake* hs = (CanaryHandshake*)m_canaryPage;
    hs->magic = 0x584D5942;
    hs->flags = 0;

    // Install VEH for guard page detection
    s_instance = this;
    m_vehHandle = AddVectoredExceptionHandler(1, VectoredHandler);
    if (!m_vehHandle) {
        m_logger->Trace(LOG_WARNING, "Canary: AddVectoredExceptionHandler failed");
        VirtualFree(m_canaryPage, 0, MEM_RELEASE);
        m_canaryPage = nullptr;
        return false;
    }

    g_canary = this;

    m_initialized = true;
    m_logger->Trace(LOG_INFO, "Canary: initialized at %p", m_canaryPage);
    return true;
}

void Canary::Shutdown()
{
    if (!m_initialized) return;

    if (m_vehHandle) {
        RemoveVectoredExceptionHandler(m_vehHandle);
        m_vehHandle = nullptr;
    }

    if (m_canaryPage) {
        VirtualFree(m_canaryPage, 0, MEM_RELEASE);
        m_canaryPage = nullptr;
    }

    s_instance = nullptr;
    if (g_canary == this) g_canary = nullptr;

    m_initialized = false;
    m_logger->Trace(LOG_INFO, "Canary: shutdown");
}

LONG CALLBACK Canary::VectoredHandler(EXCEPTION_POINTERS* ep)
{
    if (!s_instance) return EXCEPTION_CONTINUE_SEARCH;
    return s_instance->OnException(ep);
}

LONG Canary::OnException(EXCEPTION_POINTERS* ep)
{
    // Only handle access violations on our canary page
    if (ep->ExceptionRecord->ExceptionCode != STATUS_ACCESS_VIOLATION &&
        ep->ExceptionRecord->ExceptionCode != EXCEPTION_GUARD_PAGE) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    uint64_t faultAddr = ep->ExceptionRecord->ExceptionInformation[1];
    uint64_t pageBase = (uint64_t)m_canaryPage;

    if (faultAddr < pageBase || faultAddr >= pageBase + 0x1000) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    m_logger->Trace(LOG_INFO, "Canary: access detected at offset 0x%llX (op=%llu)",
        faultAddr - pageBase,
        ep->ExceptionRecord->ExceptionInformation[0]);

    if (m_captureLogger) {
        m_captureLogger->CaptureCanaryHit(ep->ContextRecord->Rip, (void*)faultAddr);
    }

    // Mark that a scan was detected
    CanaryHandshake* hs = (CanaryHandshake*)m_canaryPage;
    hs->flags |= 0x1;

    // Remove the guard and resume execution
    DWORD oldProtect;
    VirtualProtect(m_canaryPage, 0x1000, PAGE_READWRITE, &oldProtect);

    return EXCEPTION_CONTINUE_EXECUTION;
}