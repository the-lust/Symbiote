#pragma once
#include <cstdint>

class TimingProfile {
public:
    TimingProfile();
    ~TimingProfile();

    void LoadFromConfig(class ConfigParser* config = nullptr);

    uint64_t GetTscFrequency() const { return m_tscFrequency; }
    uint64_t GetTscOffset() const { return m_tscOffset; }
    uint64_t GetApicFrequency() const { return m_apicFrequency; }

    void SetTscFrequency(uint64_t freq) { m_tscFrequency = freq; }
    void SetTscOffset(uint64_t offset) { m_tscOffset = offset; }
    void SetApicFrequency(uint64_t freq) { m_apicFrequency = freq; }

private:
    uint64_t m_tscFrequency;
    uint64_t m_tscOffset;
    uint64_t m_apicFrequency;
};
