#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <windows.h>
#include "Logger.h"

class ConfigParser;
class ModuleCloak;

class ProcessEmu {
public:
    ProcessEmu(Logger* logger, ModuleCloak* cloak = nullptr);

    void LoadFromConfig(ConfigParser* config);
    void BuildVirtualProcessList();

    bool HandleNtQuerySystemInformation(uint64_t* args, uint64_t* result);
    bool HandleNtQueryInformationProcess(uint64_t* args, uint64_t* result);
    bool HandleNtOpenProcess(uint64_t* args, uint64_t* result);
    uint64_t GetSpoofedPebField(uint32_t offset);

private:
    Logger* m_logger;
    ModuleCloak* m_moduleCloak;

    struct VirtualProcessInfo {
        uint64_t uniqueProcessId;
        uint64_t parentProcessId;
        std::wstring imageName;
        uint32_t sessionId;
        uint32_t handleCount;
        uint32_t threadCount;
    };
    std::vector<VirtualProcessInfo> m_virtualProcessList;

    // Configurable system info
    uint32_t m_processorCount;
    uint64_t m_affinityMask;
    uint32_t m_physicalPageCount;
    uint32_t m_timerResolution;

    // SMBIOS strings (configurable)
    std::string m_biosVendor;
    std::string m_biosVersion;
    std::string m_biosDate;
    std::string m_manufacturer;
    std::string m_productName;
    std::string m_productVersion;
    std::string m_serialNumber;
    std::string m_chassisSerial;
    std::string m_baseboardSerial;
    std::string m_sku;
    std::string m_family;
};
