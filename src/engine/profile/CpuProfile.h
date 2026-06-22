#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>

class ConfigParser;

class CpuProfile {
public:
    CpuProfile();
    ~CpuProfile();

    void LoadFromConfig();
    void LoadFromConfig(ConfigParser* config);
    void LoadAmdProfile();

    bool GetSpoof(uint32_t leaf, uint32_t subleaf, uint32_t* eax, uint32_t* ebx,
                  uint32_t* ecx, uint32_t* edx) const;

    void SetLeaf(uint32_t leaf, uint32_t subleaf, uint32_t eax, uint32_t ebx,
                 uint32_t ecx, uint32_t edx);
    bool GetLeaf(uint32_t leaf, uint32_t subleaf, uint32_t* eax, uint32_t* ebx,
                 uint32_t* ecx, uint32_t* edx) const;

    void SetBrandString(const std::string& brand);
    void EncodeBrandToLeaves(uint32_t startLeaf);

    uint64_t GetTscFrequency() const { return m_tscFrequency; }
    void SetTscFrequency(uint64_t freq) { m_tscFrequency = freq; }

private:
    struct CpuLeaf {
        uint32_t eax, ebx, ecx, edx;
    };

    std::unordered_map<uint64_t, CpuLeaf> m_leaves;
    uint64_t m_tscFrequency;
    std::string m_brandString;
};
