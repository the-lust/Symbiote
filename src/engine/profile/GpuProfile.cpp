#include "GpuProfile.h"
#include "ConfigParser.h"

GpuProfile::GpuProfile()
    : m_vendorId(0x1002), m_deviceId(0x73BF),
      m_subsystemId(0x0E1D1002), m_revisionId(0xC1),
      m_deviceName("AMD Radeon RX 6800 XT")
{
}

GpuProfile::~GpuProfile()
{
}

void GpuProfile::LoadFromConfig(ConfigParser* config)
{
    if (!config) return;

    m_vendorId = static_cast<uint16_t>(config->GetUint64("gpu", "vendor_id", m_vendorId));
    m_deviceId = static_cast<uint16_t>(config->GetUint64("gpu", "device_id", m_deviceId));
    m_subsystemId = static_cast<uint32_t>(config->GetUint64("gpu", "subsystem_id", m_subsystemId));
    m_revisionId = static_cast<uint8_t>(config->GetUint64("gpu", "revision_id", m_revisionId));
    m_deviceName = config->GetString("gpu", "device_name", m_deviceName);
}
