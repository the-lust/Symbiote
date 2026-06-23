#pragma once
#include <cstdint>
#include <unordered_map>
#include <string>

class ConfigParser;

struct CpuidLeaf {
    uint32_t eax, ebx, ecx, edx;
};

class SystemProfile {
public:
    SystemProfile();
    ~SystemProfile() = default;

    void LoadFromConfig(ConfigParser* config);

    // CPUID
    bool GetCpuid(uint32_t leaf, uint32_t subleaf, uint32_t& eax, uint32_t& ebx, uint32_t& ecx, uint32_t& edx) const;
    void SetCpuid(uint32_t leaf, uint32_t subleaf, uint32_t eax, uint32_t ebx, uint32_t ecx, uint32_t edx);

    // Processor info
    uint64_t GetTscFrequency() const { return m_tscFrequency; }
    void SetTscFrequency(uint64_t hz) { m_tscFrequency = hz; }

    uint64_t GetTscOffset() const { return m_tscOffset; }
    void SetTscOffset(uint64_t offset) { m_tscOffset = offset; }

    uint64_t GetApicFrequency() const { return m_apicFrequency; }
    void SetApicFrequency(uint64_t freq) { m_apicFrequency = freq; }

    uint32_t GetProcessorCount() const { return m_processorCount; }
    void SetProcessorCount(uint32_t count) { m_processorCount = count; }

    const char* GetBrandString() const { return m_brandString.c_str(); }
    void SetBrandString(const char* str) { m_brandString = str ? str : ""; EncodeBrandToLeaves(0x80000002); }
    void SetBrandString(const std::string& str) { m_brandString = str; EncodeBrandToLeaves(0x80000002); }
    void EncodeBrandToLeaves(uint32_t startLeaf);

    // System info for KUSER
    uint16_t GetNtMajorVersion() const { return m_ntMajorVersion; }
    uint16_t GetNtMinorVersion() const { return m_ntMinorVersion; }
    uint16_t GetNtBuildNumber() const { return m_ntBuildNumber; }
    void SetNtVersion(uint16_t major, uint16_t minor, uint16_t build) {
        m_ntMajorVersion = major; m_ntMinorVersion = minor; m_ntBuildNumber = build;
    }

    // GPU
    uint32_t GetGpuVendor() const { return m_gpuVendor; }
    const char* GetGpuName() const { return m_gpuName.c_str(); }
    void SetGpu(uint32_t vendor, const char* name) { m_gpuVendor = vendor; m_gpuName = name ? name : ""; }

    // Load predefined profiles
    void LoadIntelI9_10900K();
    void LoadAmdRyzen9_5950X();

private:
    std::unordered_map<uint32_t, CpuidLeaf> m_cpuidLeaves;
    uint64_t m_tscFrequency;
    uint64_t m_tscOffset;
    uint64_t m_apicFrequency;
    uint32_t m_processorCount;
    std::string m_brandString;

    uint16_t m_ntMajorVersion = 10;
    uint16_t m_ntMinorVersion = 0;
    uint16_t m_ntBuildNumber = 19041;

    uint32_t m_gpuVendor = 0x1002; // AMD
    std::string m_gpuName;
};
