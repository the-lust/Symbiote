#include "TimingProfile.h"
#include "ConfigParser.h"

TimingProfile::TimingProfile()
    : m_tscFrequency(3700000000ULL),
      m_tscOffset(0ULL),
      m_apicFrequency(100000000ULL)
{
}

TimingProfile::~TimingProfile()
{
}

void TimingProfile::LoadFromConfig(ConfigParser* config)
{
    if (!config) return;

    m_tscFrequency = config->GetUint64("timing", "tsc_frequency", m_tscFrequency);
    m_tscOffset = config->GetUint64("timing", "tsc_offset", m_tscOffset);
    m_apicFrequency = config->GetUint64("timing", "apic_frequency", m_apicFrequency);
}
