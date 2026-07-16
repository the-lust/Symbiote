#include "ApiSetResolver.h"
#include <winternl.h>
#include <intrin.h>

// V6 ApiSet schema structures (Windows 10+)
#pragma pack(push, 1)
struct API_SET_NAMESPACE_V6 {
    ULONG Version;
    ULONG Size;
    ULONG Count;
    ULONG EntryOffset;
    ULONG HashEntryCount;
    ULONG HashEntryOffset;
};

struct API_SET_NAMESPACE_ENTRY_V6 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG HashedLength;
    ULONG ValueOffset;
    ULONG ValueCount;
};

struct API_SET_VALUE_ENTRY_V6 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
};
#pragma pack(pop)

#define ASET_LOG(fmt, ...) if (m_logger) m_logger->Trace(LOG_PROXY, "ApiSet: " fmt, ##__VA_ARGS__)

ApiSetResolver::ApiSetResolver(Logger* logger)
    : m_logger(logger), m_initialized(false)
{
}

ApiSetResolver::~ApiSetResolver()
{
}

uintptr_t ApiSetResolver::FindApiSetMap()
{
    // PEB is at GS:[0x60] on x64
    PPEB peb = (PPEB)__readgsqword(0x60);
    if (!peb) return 0;

    // On Windows 10+, ApiSetMap is at peb->Reserved[0] offset
    // This is peb+0x38 for x64, peb+0x1C for x86
    uintptr_t* rawPtr = (uintptr_t*)peb;
    uintptr_t apiSetMap = rawPtr[7];  // offset 0x38 = index 7 in uintptr_t array
    if (!apiSetMap) return 0;

    // Validate by checking the version field
    API_SET_NAMESPACE_V6* ns = (API_SET_NAMESPACE_V6*)apiSetMap;
    if (ns->Version >= 6 && ns->Version <= 7 && ns->Size > 0 && ns->Count > 0) {
        ASET_LOG("found V%u ApiSet schema at 0x%llX, %u entries, size %u",
            ns->Version, (uint64_t)apiSetMap, ns->Count, ns->Size);
        return apiSetMap;
    }

    return 0;
}

bool ApiSetResolver::ParseV6()
{
    uintptr_t nsBase = FindApiSetMap();
    if (!nsBase) {
        ASET_LOG("no V6 ApiSet schema found");
        return false;
    }

    API_SET_NAMESPACE_V6* ns = (API_SET_NAMESPACE_V6*)nsBase;
    API_SET_NAMESPACE_ENTRY_V6* entries = (API_SET_NAMESPACE_ENTRY_V6*)(nsBase + ns->EntryOffset);

    uint32_t parsed = 0;
    for (ULONG i = 0; i < ns->Count && i < 4096; i++) {
        API_SET_NAMESPACE_ENTRY_V6* entry = &entries[i];

        // Get the API set name (the contract DLL name like "api-ms-win-core-synch-l1-2-0")
        wchar_t* entryName = (wchar_t*)(nsBase + entry->NameOffset);
        ULONG nameChars = entry->NameLength / sizeof(wchar_t);

        if (nameChars == 0 || nameChars > 256) continue;

        std::wstring apiSetName(entryName, nameChars);
        // Lowercase for consistent lookup
        for (auto& c : apiSetName) c = towlower(c);

        // Get the host DLL name from the first value entry
        if (entry->ValueCount > 0) {
            API_SET_VALUE_ENTRY_V6* valueEntry = (API_SET_VALUE_ENTRY_V6*)(nsBase + entry->ValueOffset);
            wchar_t* valueName = (wchar_t*)(nsBase + valueEntry->NameOffset);
            ULONG valueChars = valueEntry->NameLength / sizeof(wchar_t);

            if (valueChars > 0 && valueChars < 256) {
                std::wstring hostDll(valueName, valueChars);
                for (auto& c : hostDll) c = towlower(c);

                // Only add if host DLL is different from the API set name
                if (apiSetName != hostDll) {
                    m_mappings[apiSetName] = hostDll;
                    parsed++;
                }
            }
        }
    }

    ASET_LOG("parsed %u API set mappings", parsed);
    return parsed > 0;
}

bool ApiSetResolver::Initialize()
{
    if (m_initialized) return true;
    m_initialized = ParseV6();

    if (m_initialized) {
        ASET_LOG("resolver initialized with %llu entries",
            (unsigned long long)m_mappings.size());
    } else {
        ASET_LOG("resolver initialization failed — no API set data");
    }
    return m_initialized;
}

std::wstring ApiSetResolver::Resolve(const std::wstring& apiSetName) const
{
    std::wstring lower = apiSetName;
    for (auto& c : lower) c = towlower(c);

    auto it = m_mappings.find(lower);
    if (it != m_mappings.end()) return it->second;

    // Strip ".dll" suffix and try again — some contracts are queried without extension
    if (lower.size() > 4 && lower.substr(lower.size() - 4) == L".dll") {
        std::wstring withoutExt = lower.substr(0, lower.size() - 4);
        it = m_mappings.find(withoutExt);
        if (it != m_mappings.end()) return it->second;
    }

    return apiSetName;  // Return as-is if not an API set
}

const std::unordered_map<std::wstring, std::wstring>& ApiSetResolver::GetMappings() const
{
    return m_mappings;
}

void ApiSetResolver::LogCoverage() const
{
    if (!m_initialized || m_mappings.empty()) {
        ASET_LOG("coverage: no API set data available");
        return;
    }

    // List of proxy DLLs we currently ship
    static const wchar_t* kProxyDlls[] = {
        L"kernel32.dll", L"kernelbase.dll", L"ntdll.dll",
        L"advapi32.dll", L"user32.dll", L"wbem.dll",
        L"wtsapi32.dll", L"secur32.dll", L"crypt32.dll",
        L"winhttp.dll", L"dnsapi.dll", L"iphlpapi.dll",
        L"ws2_32.dll"
    };

    int covered = 0;
    int missed = 0;

    ASET_LOG("coverage: checking %llu API set mappings against %zu proxy DLLs",
        (unsigned long long)m_mappings.size(), ARRAYSIZE(kProxyDlls));

    for (const auto& pair : m_mappings) {
        bool found = false;
        for (auto proxy : kProxyDlls) {
            std::wstring proxyLower = proxy;
            for (auto& c : proxyLower) c = towlower(c);
            if (pair.second == proxyLower) {
                found = true;
                break;
            }
        }
        if (found) covered++;
        else {
            if (missed < 20) {  // Log only first 20 misses
                ASET_LOG("coverage gap: %ls -> %ls", pair.first.c_str(), pair.second.c_str());
            }
        }
        missed++;
    }

    ASET_LOG("coverage: %d API sets map to known proxy DLLs, %d to uncovered DLLs",
        covered, missed);
}
