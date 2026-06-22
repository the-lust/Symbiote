#pragma once
#include <cstdint>
#include <string>

class GpuProfile {
public:
    GpuProfile();
    ~GpuProfile();

    void LoadFromConfig(class ConfigParser* config = nullptr);

    uint16_t GetVendorId() const { return m_vendorId; }
    uint16_t GetDeviceId() const { return m_deviceId; }
    uint32_t GetSubsystemId() const { return m_subsystemId; }
    uint8_t GetRevisionId() const { return m_revisionId; }

    void SetVendorId(uint16_t id) { m_vendorId = id; }
    void SetDeviceId(uint16_t id) { m_deviceId = id; }
    void SetSubsystemId(uint32_t id) { m_subsystemId = id; }
    void SetRevisionId(uint8_t id) { m_revisionId = id; }

    std::string GetDeviceName() const { return m_deviceName; }

private:
    uint16_t m_vendorId;
    uint16_t m_deviceId;
    uint32_t m_subsystemId;
    uint8_t m_revisionId;
    std::string m_deviceName;
};
