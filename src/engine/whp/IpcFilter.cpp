// Credits: ALPC/pipe block list pattern adapted from Sandboxie (https://github.com/sandboxie-plus/Sandboxie)
#include "IpcFilter.h"

IpcFilter* g_ipcFilter = nullptr;

const wchar_t* IpcFilter::kEscapePorts[] = {
    // ALPC escape vectors — Sandboxie derived
    L"\\RPC Control\\sbiedll",
    L"\\RPC Control\\sbievc",
    L"\\RPC Control\\sbiectrl",
    L"\\RPC Control\\sbieSvc",
    L"\\RPC Control\\WindowsSandboxClient",
    L"\\RPC Control\\lsass",
    L"\\RPC Control\\samr",
    L"\\RPC Control\\protected_audio",
    L"\\RPC Control\\netlogon",
    L"\\RPC Control\\spoolss",
    L"\\RPC Control\\epmapper",
    L"\\RPC Control\\DNSResolver",
    L"\\RPC Control\\OLE",
    L"\\RPC Control\\WindowsShutdown",
    L"\\Windows\\ApiPort",
    L"\\SmApiPort",
    L"\\DbgSsApiPort",
    L"\\DbgUiApiPort",

    // DRM / anti-cheat evasion — Denuvo + EAC + BattlEye
    // Denuvo token validation and anti-debug communication ports
    L"\\RPC Control\\DenuvoToken",
    L"\\RPC Control\\DenuvoClient",
    L"\\RPC Control\\DenuvOService",
    L"\\RPC Control\\denuvo_anti_debug",
    // EAC user-mode service communication
    L"\\RPC Control\\EasyAntiCheat",
    L"\\RPC Control\\EACService",
    L"\\RPC Control\\EasyAntiCheat_Server",
    L"\\RPC Control\\EasyAntiCheat_Client",
    // BattlEye service ports
    L"\\RPC Control\\BEDaisy",
    L"\\RPC Control\\BattlEye",
    L"\\RPC Control\\BEService",
    // Anti-cheat detection tool ports
    L"\\RPC Control\\vmdetect",
    L"\\RPC Control\\hyperv_check",
    L"\\RPC Control\\antivm",
    L"\\RPC Control\\vmware_check",
    L"\\RPC Control\\vbox_check",

    // Named pipe escape vectors
    L"\\Device\\NamedPipe\\lsass",
    L"\\Device\\NamedPipe\\samr",
    L"\\Device\\NamedPipe\\srvsvc",
    L"\\Device\\NamedPipe\\sbie",
    L"\\Device\\NamedPipe\\sbiedll",
    // Anti-cheat named pipes
    L"\\Device\\NamedPipe\\EasyAntiCheat",
    L"\\Device\\NamedPipe\\EAC",
    L"\\Device\\NamedPipe\\BattlEye",
    L"\\Device\\NamedPipe\\BEDaisy",
    // Virtual machine detection pipes
    L"\\Device\\NamedPipe\\VMwareGuest",
    L"\\Device\\NamedPipe\\VBoxGuest",
    L"\\Device\\NamedPipe\\hyperv_guest",
};

const uint32_t IpcFilter::kEscapePortCount = sizeof(kEscapePorts) / sizeof(kEscapePorts[0]);

IpcFilter::IpcFilter(Logger* logger)
    : m_logger(logger)
    , m_initialized(false)
    , m_defaultAction(ACTION_ALLOW)
{
}

IpcFilter::~IpcFilter()
{
    g_ipcFilter = nullptr;
}

bool IpcFilter::Initialize()
{
    for (uint32_t i = 0; i < kEscapePortCount; i++) {
        IpcRule r;
        r.portName = kEscapePorts[i];
        r.action = ACTION_BLOCK;
        r.isAlpc = (wcsstr(kEscapePorts[i], L"\\Device\\NamedPipe\\") != 0) ? false : true;
        m_rules.push_back(r);
    }

    m_initialized = true;
    m_logger->Trace(LOG_INFO, "IpcFilter: initialized (%u escape ports blocked)", kEscapePortCount);
    return true;
}

void IpcFilter::AddRule(const IpcRule& rule)
{
    m_rules.push_back(rule);
}

bool IpcFilter::ShouldBlockAlpc(const wchar_t* portName)
{
    BlockAction action;
    if (MatchRule(portName, true, action)) {
        return (action == ACTION_BLOCK);
    }
    return (m_defaultAction == ACTION_BLOCK);
}

bool IpcFilter::ShouldBlockPipe(const wchar_t* pipeName)
{
    BlockAction action;
    if (MatchRule(pipeName, false, action)) {
        return (action == ACTION_BLOCK);
    }
    return (m_defaultAction == ACTION_BLOCK);
}

bool IpcFilter::MatchRule(const wchar_t* name, bool isAlpc, BlockAction& action)
{
    if (!name || !name[0]) return false;

    for (const auto& rule : m_rules) {
        if (rule.isAlpc != isAlpc) continue;

        size_t len = rule.portName.length();
        if (_wcsnicmp(name, rule.portName.c_str(), len) == 0) {
            action = rule.action;
            return true;
        }
    }

    return false;
}
