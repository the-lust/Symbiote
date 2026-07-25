// Credits: Registry COW + delete marks pattern adapted from Sandboxie (https://github.com/sandboxie-plus/Sandboxie)
#include "RegistryRedirection.h"
#include <algorithm>

RegistryRedirection* g_registryRedirection = nullptr;

RegistryRedirection::RegistryRedirection(Logger* logger)
    : m_logger(logger)
    , m_initialized(false)
{
}

RegistryRedirection::~RegistryRedirection()
{
    g_registryRedirection = nullptr;
}

bool RegistryRedirection::Initialize(const wchar_t* boxName)
{
    m_boxName = boxName;
    m_boxRoot = L"\\Sandbox\\" + std::wstring(boxName) + L"\\Registry\\";

    m_rules.clear();

    KeyRule userRule;
    userRule.hostKeyPrefix = L"\\REGISTRY\\USER\\";
    userRule.boxKeyPrefix = L"\\Sandbox\\" + std::wstring(boxName) + L"\\Registry\\USER\\";
    userRule.readOnly = false;
    userRule.recursive = true;
    m_rules.push_back(userRule);

    KeyRule machineRule;
    machineRule.hostKeyPrefix = L"\\REGISTRY\\MACHINE\\SOFTWARE\\";
    machineRule.boxKeyPrefix = L"\\Sandbox\\" + std::wstring(boxName) + L"\\Registry\\MACHINE\\SOFTWARE\\";
    machineRule.readOnly = true;
    machineRule.recursive = true;
    m_rules.push_back(machineRule);

    KeyRule machineReadWrite;
    machineReadWrite.hostKeyPrefix = L"\\REGISTRY\\MACHINE\\SYSTEM\\";
    machineReadWrite.boxKeyPrefix = L"\\Sandbox\\" + std::wstring(boxName) + L"\\Registry\\MACHINE\\SYSTEM\\";
    machineReadWrite.readOnly = true;
    machineReadWrite.recursive = true;
    m_rules.push_back(machineReadWrite);

    m_initialized = true;
    m_logger->Trace(LOG_INFO, "RegistryRedirection: initialized for box '%ls'", boxName);
    return true;
}

void RegistryRedirection::AddRule(const KeyRule& rule)
{
    m_rules.push_back(rule);
}

bool RegistryRedirection::GetRedirectedKey(const wchar_t* hostKey, std::wstring& outBoxKey, bool isWrite)
{
    if (!m_initialized) return false;

    std::wstring norm = NormalizeKey(hostKey);
    if (norm.empty()) return false;

    for (const auto& rule : m_rules) {
        std::wstring relative;
        if (IsKeyUnderRule(norm, rule, relative)) {
            if (isWrite) {
                outBoxKey = rule.boxKeyPrefix + relative;
                return true;
            }
            if (rule.readOnly) {
                outBoxKey = norm;
                return true;
            }
            outBoxKey = rule.boxKeyPrefix + relative;
            return true;
        }
    }

    outBoxKey = norm;
    return false;
}

bool RegistryRedirection::GetTrueKey(const wchar_t* boxKey, std::wstring& outHostKey)
{
    std::wstring norm = NormalizeKey(boxKey);
    if (norm.empty()) return false;

    for (const auto& rule : m_rules) {
        if (norm.find(rule.boxKeyPrefix) == 0) {
            outHostKey = rule.hostKeyPrefix + norm.substr(rule.boxKeyPrefix.length());
            return true;
        }
    }

    outHostKey = norm;
    return false;
}

bool RegistryRedirection::EnsureWriteCopy(const wchar_t* hostKey)
{
    std::wstring boxKey;
    if (!GetRedirectedKey(hostKey, boxKey, true))
        return false;

    if (boxKey == NormalizeKey(hostKey))
        return true;

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, boxKey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }

    return CopyKeyToBox(hostKey, boxKey.c_str());
}

bool RegistryRedirection::IsDeleted(const wchar_t* hostKey)
{
    std::wstring norm = NormalizeKey(hostKey);
    auto it = m_deletedKeys.find(norm);
    return it != m_deletedKeys.end() && it->second;
}

bool RegistryRedirection::MarkDeleted(const wchar_t* hostKey)
{
    std::wstring norm = NormalizeKey(hostKey);
    m_deletedKeys[norm] = true;
    return true;
}

bool RegistryRedirection::UnmarkDeleted(const wchar_t* hostKey)
{
    std::wstring norm = NormalizeKey(hostKey);
    m_deletedKeys.erase(norm);
    return true;
}

bool RegistryRedirection::EnumerateMerged(const wchar_t* hostKey,
                                           std::vector<std::wstring>& outSubKeys,
                                           std::vector<std::wstring>& outValues)
{
    std::wstring norm = NormalizeKey(hostKey);
    std::vector<std::wstring> boxKeys;
    std::vector<std::wstring> boxVals;

    std::wstring boxKey;
    GetRedirectedKey(norm.c_str(), boxKey, false);

    HKEY hHost = NULL;
    HKEY hBox = NULL;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, norm.c_str(), 0, KEY_ENUMERATE_SUB_KEYS, &hHost) == ERROR_SUCCESS) {
        for (DWORD i = 0; ; i++) {
            wchar_t name[256];
            DWORD nameLen = 256;
            if (RegEnumKeyExW(hHost, i, name, &nameLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
                break;
            outSubKeys.push_back(name);
        }
        for (DWORD i = 0; ; i++) {
            wchar_t name[16384];
            DWORD nameLen = 16384;
            if (RegEnumValueW(hHost, i, name, &nameLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
                break;
            outValues.push_back(name);
        }
        RegCloseKey(hHost);
    }

    if (!boxKey.empty() && boxKey != norm) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, boxKey.c_str(), 0, KEY_ENUMERATE_SUB_KEYS, &hBox) == ERROR_SUCCESS) {
            for (DWORD i = 0; ; i++) {
                wchar_t name[256];
                DWORD nameLen = 256;
                if (RegEnumKeyExW(hBox, i, name, &nameLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
                    break;
                bool found = false;
                for (const auto& e : outSubKeys) {
                    if (_wcsicmp(e.c_str(), name) == 0) { found = true; break; }
                }
                if (!found) outSubKeys.push_back(name);
            }
            for (DWORD i = 0; ; i++) {
                wchar_t name[16384];
                DWORD nameLen = 16384;
                if (RegEnumValueW(hBox, i, name, &nameLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
                    break;
                bool found = false;
                for (const auto& e : outValues) {
                    if (_wcsicmp(e.c_str(), name) == 0) { found = true; break; }
                }
                if (!found) outValues.push_back(name);
            }
            RegCloseKey(hBox);
        }
    }

    return true;
}

bool RegistryRedirection::Resolve(const wchar_t* path, bool isWrite, KeyInfo& info)
{
    std::wstring norm = NormalizeKey(path);
    info.truePath = norm;
    info.isDeleted = IsDeleted(norm.c_str());

    if (GetRedirectedKey(norm.c_str(), info.boxPath, isWrite)) {
        info.isRedirected = (info.boxPath != norm);
        return true;
    }

    info.boxPath = norm;
    info.isRedirected = false;
    return true;
}

bool RegistryRedirection::IsKeyUnderRule(const std::wstring& key, const KeyRule& rule, std::wstring& relative)
{
    if (key.find(rule.hostKeyPrefix) != 0) return false;
    relative = key.substr(rule.hostKeyPrefix.length());
    return true;
}

std::wstring RegistryRedirection::NormalizeKey(const wchar_t* key)
{
    if (!key || !key[0]) return L"";
    std::wstring result = key;
    for (size_t i = 0; i < result.length(); i++) {
        if (result[i] == L'/') result[i] = L'\\';
    }
    // Registry is case-insensitive; normalize to uppercase for consistent comparison
    std::transform(result.begin(), result.end(), result.begin(), ::towupper);
    return result;
}

bool RegistryRedirection::CopyKeyToBox(const wchar_t* hostKey, const wchar_t* boxKey)
{
    HKEY hSrc;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, hostKey, 0, KEY_READ, &hSrc) != ERROR_SUCCESS)
        return false;

    HKEY hDst;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, boxKey, 0, NULL, 0,
        KEY_WRITE, NULL, &hDst, NULL) != ERROR_SUCCESS) {
        RegCloseKey(hSrc);
        return false;
    }

    for (DWORD i = 0; ; i++) {
        wchar_t valueName[16384];
        DWORD valueNameLen = 16384;
        DWORD type = 0;
        BYTE data[65536];
        DWORD dataLen = sizeof(data);

        LONG ret = RegEnumValueW(hSrc, i, valueName, &valueNameLen,
            NULL, &type, data, &dataLen);
        if (ret != ERROR_SUCCESS) break;

        RegSetValueExW(hDst, valueName, 0, type, data, dataLen);
    }

    RegCloseKey(hDst);
    RegCloseKey(hSrc);
    return true;
}

bool RegistryRedirection::ShouldRedirect(const wchar_t* keyPath) const
{
    if (!m_initialized || !keyPath) return false;

    std::wstring norm;
    norm.resize(wcslen(keyPath) + 1);
    norm.assign(keyPath);
    for (size_t i = 0; i < norm.length(); i++) {
        if (norm[i] == L'/') norm[i] = L'\\';
    }
    std::transform(norm.begin(), norm.end(), norm.begin(), ::towupper);

    for (const auto& rule : m_rules) {
        if (norm.find(rule.hostKeyPrefix) == 0) {
            return true;
        }
    }

    // Default: redirect registry paths that could leak virtualized environment info
    static const wchar_t* kRedirectedPaths[] = {
        L"\\REGISTRY\\MACHINE\\SOFTWARE\\MICROSOFT\\HYPER-V",
        L"\\REGISTRY\\MACHINE\\SOFTWARE\\MICROSOFT\\VIRTUAL MACHINE",
        L"\\REGISTRY\\MACHINE\\HARDWARE\\DESCRIPTION\\SYSTEM\\BIOS",
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CONTROLSET001\\SERVICES\\VMTRAY",
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CONTROLSET001\\SERVICES\\VBOXGUEST",
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CONTROLSET001\\SERVICES\\VMSCI",
        nullptr
    };

    for (int i = 0; kRedirectedPaths[i]; i++) {
        if (norm.find(kRedirectedPaths[i]) == 0) {
            return true;
        }
    }

    return false;
}

bool RegistryRedirection::GetRedirectedValue(const wchar_t* keyPath, const wchar_t* valueName, RedirectedValue& outValue) const
{
    if (!m_initialized || !keyPath || !valueName) return false;

    // Sanitize values that may report inconsistent virtualized environment info
    std::wstring normKey;
    normKey.assign(keyPath);
    for (size_t i = 0; i < normKey.length(); i++) {
        if (normKey[i] == L'/') normKey[i] = L'\\';
    }
    std::transform(normKey.begin(), normKey.end(), normKey.begin(), ::towupper);

    std::wstring normVal;
    normVal.assign(valueName);
    std::transform(normVal.begin(), normVal.end(), normVal.begin(), ::towupper);

    // Known registry values to sanitize for environment consistency
    struct {
        const wchar_t* keyPattern;
        const wchar_t* valuePattern;
        uint32_t type;
        const uint8_t* data;
        uint32_t dataSize;
    } kSpoofedValues[] = {
        // Hyper-V presence: return "not present"
        { L"SOFTWARE\\MICROSOFT\\HYPER-V", L"INSTALLED", REG_DWORD },
        { L"SOFTWARE\\MICROSOFT\\VIRTUAL MACHINE", L"INSTALLED", REG_DWORD },
        // BIOS vendor: return a real vendor
        { L"DESCRIPTION\\SYSTEM\\BIOS", L"BIOSVENDOR", REG_SZ },
        { L"DESCRIPTION\\SYSTEM\\BIOS", L"SYSTEMMANUFACTURER", REG_SZ },
        { L"DESCRIPTION\\SYSTEM\\BIOS", L"SYSTEMPRODUCTNAME", REG_SZ },
        // CPU vendor: match our spoofed CPUID
        { L"DESCRIPTION\\SYSTEM\\CENTRALPROCESSOR\\0", L"VENDORIDENTIFIER", REG_SZ },
        { L"DESCRIPTION\\SYSTEM\\CENTRALPROCESSOR\\0", L"PROCESSORNAMESTRING", REG_SZ },
    };

    for (const auto& sv : kSpoofedValues) {
        if (normKey.find(sv.keyPattern) != std::wstring::npos &&
            normVal == sv.valuePattern) {
            // Build spoofed value data per entry
            outValue.type = sv.type;
            if (wcscmp(sv.valuePattern, L"INSTALLED") == 0) {
                // DWORD 0 = not installed
                uint32_t zero = 0;
                outValue.data.resize(sizeof(zero));
                memcpy(outValue.data.data(), &zero, sizeof(zero));
            } else if (wcscmp(sv.valuePattern, L"BIOSVENDOR") == 0) {
                std::wstring val = L"American Megatrends Inc.";
                outValue.data.resize((val.length() + 1) * sizeof(wchar_t));
                memcpy(outValue.data.data(), val.c_str(), (val.length() + 1) * sizeof(wchar_t));
            } else if (wcscmp(sv.valuePattern, L"SYSTEMMANUFACTURER") == 0) {
                std::wstring val = L"Dell Inc.";
                outValue.data.resize((val.length() + 1) * sizeof(wchar_t));
                memcpy(outValue.data.data(), val.c_str(), (val.length() + 1) * sizeof(wchar_t));
            } else if (wcscmp(sv.valuePattern, L"SYSTEMPRODUCTNAME") == 0) {
                std::wstring val = L"Precision Tower 5810";
                outValue.data.resize((val.length() + 1) * sizeof(wchar_t));
                memcpy(outValue.data.data(), val.c_str(), (val.length() + 1) * sizeof(wchar_t));
            } else if (wcscmp(sv.valuePattern, L"VENDORIDENTIFIER") == 0) {
                std::wstring val = L"GenuineIntel";
                outValue.data.resize((val.length() + 1) * sizeof(wchar_t));
                memcpy(outValue.data.data(), val.c_str(), (val.length() + 1) * sizeof(wchar_t));
            } else if (wcscmp(sv.valuePattern, L"PROCESSORNAMESTRING") == 0) {
                std::wstring val = L"Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz";
                outValue.data.resize((val.length() + 1) * sizeof(wchar_t));
                memcpy(outValue.data.data(), val.c_str(), (val.length() + 1) * sizeof(wchar_t));
            } else {
                return false;
            }
            return true;
        }
    }

    return false;
}
