#pragma once
#include <windows.h>
#include <string>
#include <unordered_map>
#include <vector>
#include "Logger.h"

class RegistryRedirection {
public:
    explicit RegistryRedirection(Logger* logger);
    ~RegistryRedirection();

    struct KeyRule {
        std::wstring hostKeyPrefix; // e.g. \REGISTRY\USER\<SID>\Software
        std::wstring boxKeyPrefix;  // e.g. \Sandbox\DefaultBox\user\current\Software
        bool         readOnly;
        bool         recursive;
    };

    struct KeyInfo {
        std::wstring truePath;
        std::wstring boxPath;
        bool         isRedirected;
        bool         isDeleted;
    };

    // Holds a redirected registry value — used by EngineExports for proxy DLL queries
    struct RedirectedValue {
        std::vector<uint8_t> data;
        uint32_t type;
    };

    bool Initialize(const wchar_t* boxName);
    void AddRule(const KeyRule& rule);

    bool GetRedirectedKey(const wchar_t* hostKey, std::wstring& outBoxKey, bool isWrite);
    bool GetTrueKey(const wchar_t* boxKey, std::wstring& outHostKey);
    bool EnsureWriteCopy(const wchar_t* hostKey);

    bool IsDeleted(const wchar_t* hostKey);
    bool MarkDeleted(const wchar_t* hostKey);
    bool UnmarkDeleted(const wchar_t* hostKey);

    bool EnumerateMerged(const wchar_t* hostKey,
                         std::vector<std::wstring>& outSubKeys,
                         std::vector<std::wstring>& outValues);

    bool Resolve(const wchar_t* path, bool isWrite, KeyInfo& info);

    // Returns whether a given registry key path should be redirected
    bool ShouldRedirect(const wchar_t* keyPath) const;

    // Returns a spoofed value for the given key+name (for proxy DLL use)
    bool GetRedirectedValue(const wchar_t* keyPath, const wchar_t* valueName, RedirectedValue& outValue) const;

    bool IsInitialized() const { return m_initialized; }

private:
    Logger* m_logger;
    bool m_initialized;
    std::wstring m_boxName;
    std::wstring m_boxRoot;
    std::vector<KeyRule> m_rules;
    std::unordered_map<std::wstring, bool> m_deletedKeys;

    bool IsKeyUnderRule(const std::wstring& key, const KeyRule& rule, std::wstring& relative);
    std::wstring NormalizeKey(const wchar_t* key);
    bool CopyKeyToBox(const wchar_t* hostKey, const wchar_t* boxKey);
};

extern RegistryRedirection* g_registryRedirection;
