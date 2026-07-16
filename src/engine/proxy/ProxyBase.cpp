#include "ProxyBase.h"
#include "ModuleCloak.h"
#include <algorithm>

ProxyBase* ProxyBase::s_instance = nullptr;

ProxyBase::ProxyBase(const std::wstring& realDllPath, Logger* logger)
    : m_realDllPath(realDllPath), m_realDll(nullptr),
      m_logger(logger), m_moduleCloak(nullptr), m_spoofHandler(nullptr)
{
    s_instance = this;
}

ProxyBase::~ProxyBase()
{
    if (m_realDll) {
        FreeLibrary(m_realDll);
    }
    s_instance = nullptr;
}

bool ProxyBase::Initialize()
{
    m_realDll = LoadLibraryW(m_realDllPath.c_str());
    if (!m_realDll) {
        m_logger->Trace(LOG_ERROR, "Failed to load real DLL: %S", m_realDllPath.c_str());
        return false;
    }
    m_logger->Trace(LOG_PROXY, "Loaded real DLL: %S", m_realDllPath.c_str());

    m_moduleCloak = new ModuleCloak(m_logger);
    m_moduleCloak->CloakModule();

    return true;
}

void* ProxyBase::GetRealProc(const char* procName)
{
    if (!m_realDll) return nullptr;
    return (void*)GetProcAddress(m_realDll, procName);
}

bool ProxyBase::HookSensitiveFunctions()
{
    m_logger->Trace(LOG_PROXY, "Hooking sensitive functions — CreateThread interception requires external trampoline setup");

    // CreateThread hook is deferred: the InlineHook system in the engine
    // replaces this by installing a proper trampoline via IatPatch or
    // a VEH-based breakpoint. The raw 12-byte patch with null address
    // is removed to avoid corrupting kernel32!CreateThread.
    //
    // Future: wire a dedicated CreateThread handler through ThreadHider.

    return true;
}

void ProxyBase::SetSpoofHandler(bool (*handler)(const char*, const char*, void*, uint64_t*, uint64_t*))
{
    m_spoofHandler = handler;
}
