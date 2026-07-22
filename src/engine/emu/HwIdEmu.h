// Credits: HWID spoofing techniques adapted from negativespoofer (https://github.com/SamuelTulach/negativespoofer)
// and mutante (https://github.com/SamuelTulach/mutante) — storage serials, volume serials, S.M.A.R.T passthrough
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <windows.h>
#include "Logger.h"

class ConfigParser;

struct DiskSpoofInfo {
    std::wstring model;
    std::wstring serial;
    uint64_t sizeBytes;
};

struct VolumeSpoofInfo {
    std::wstring label;
    uint32_t serialNumber;
};

class HwIdEmu {
public:
    explicit HwIdEmu(Logger* logger);
    ~HwIdEmu();

    bool Initialize();
    void Shutdown();
    void LoadFromConfig(ConfigParser* config);

    bool IsEnabled() const { return m_enabled; }

    // Storage IOCTL handling — returns true if spoofed
    bool HandleStorageQueryProperty(void* outputBuffer, uint32_t outputLength, uint32_t diskIndex, uint64_t* result);
    bool HandleAtaPassThrough(void* inputBuffer, uint32_t inputLength, void* outputBuffer, uint32_t outputLength, uint64_t* result);
    bool HandleNvmePassThrough(void* inputBuffer, uint32_t inputLength, void* outputBuffer, uint32_t outputLength, uint64_t* result);
    bool HandleSmartQuery(void* outputBuffer, uint32_t outputLength, uint64_t* result);

    // Volume info handling
    bool HandleVolumeInformation(uint64_t buffer, uint32_t length, uint64_t* result);

    // Public accessors for proxy DLL / WMI use
    uint32_t GetDiskCount() const { return (uint32_t)m_disks.size(); }
    const DiskSpoofInfo* GetDisk(uint32_t index) const;
    const std::wstring& GetBiosVendor() const { return m_biosVendor; }
    const std::wstring& GetSystemManufacturer() const { return m_systemManufacturer; }
    const std::wstring& GetSystemProduct() const { return m_systemProduct; }
    const std::wstring& GetSystemSerial() const { return m_systemSerial; }

private:
    Logger* m_logger;
    bool m_enabled;
    bool m_initialized;

    std::vector<DiskSpoofInfo> m_disks;
    VolumeSpoofInfo m_volumeInfo;

    // System identifiers from config
    std::wstring m_biosVendor;
    std::wstring m_biosVersion;
    std::wstring m_systemManufacturer;
    std::wstring m_systemProduct;
    std::wstring m_systemSerial;
    std::wstring m_baseboardSerial;
    std::wstring m_chassisSerial;

    // Build fake serial from disk index
    std::wstring MakeFakeSerial(uint32_t index) const;
};

extern HwIdEmu* g_hwIdEmu;
