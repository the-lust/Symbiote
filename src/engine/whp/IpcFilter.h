#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include "Logger.h"

class IpcFilter {
public:
    explicit IpcFilter(Logger* logger);
    ~IpcFilter();

    enum BlockAction : uint32_t {
        ACTION_ALLOW  = 0,
        ACTION_BLOCK  = 1,
        ACTION_REDIRECT = 2,
    };

    struct IpcRule {
        std::wstring portName;  // ALPC port name or pipe name prefix
        BlockAction  action;
        bool         isAlpc;    // true=ALPC, false=named pipe
    };

    bool Initialize();
    void AddRule(const IpcRule& rule);

    bool ShouldBlockAlpc(const wchar_t* portName);
    bool ShouldBlockPipe(const wchar_t* pipeName);

    bool SetDefaultAction(BlockAction action) { m_defaultAction = action; return true; }

    bool IsInitialized() const { return m_initialized; }

    // Known escape vectors
    static const wchar_t* kEscapePorts[];
    static const uint32_t kEscapePortCount;

private:
    Logger* m_logger;
    bool m_initialized;
    BlockAction m_defaultAction;
    std::vector<IpcRule> m_rules;

    bool MatchRule(const wchar_t* name, bool isAlpc, BlockAction& action);
};

extern IpcFilter* g_ipcFilter;
