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
    m_logger->Trace(LOG_PROXY, "Hooking sensitive functions");

    // Hook kernel32!CreateThread to route through proxy
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32) {
        void* createThread = GetProcAddress(hKernel32, "CreateThread");
        if (createThread) {
            // 12-byte inline hook — redirect to proxy handler
            DWORD old;
            VirtualProtect(createThread, 12, PAGE_EXECUTE_READWRITE, &old);
            uint8_t* p = (uint8_t*)createThread;
            // Save original bytes (not implemented here — caller handles)
            p[0] = 0x48; p[1] = 0xB8; // mov rax, imm64
            // Store address of a trampoline handler (to be set by caller)
            *(uint64_t*)&p[2] = 0;
            p[10] = 0xFF; p[11] = 0xE0; // jmp rax
            VirtualProtect(createThread, 12, old, &old);
            FlushInstructionCache(GetCurrentProcess(), createThread, 12);
            m_logger->Trace(LOG_PROXY, "HookSensitiveFunctions: CreateThread hooked");
        }
    }

    return true;
}

void ProxyBase::SetSpoofHandler(bool (*handler)(const char*, const char*, void*, uint64_t*, uint64_t*))
{
    m_spoofHandler = handler;
}
