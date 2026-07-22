// Credits: HWID spoofing techniques adapted from negativespoofer (https://github.com/SamuelTulach/negativespoofer)
// and mutante (https://github.com/SamuelTulach/mutante) — storage serials, volume serials, ATA/NVMe pass-through
#define WIN32_NO_STATUS
#include "HwIdEmu.h"
#include "ConfigParser.h"
#include <winioctl.h>
#include <ntddstor.h>
#include <cstring>
#include <sstream>
#include <iomanip>
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#undef WIN32_NO_STATUS
#include <ntstatus.h>

HwIdEmu* g_hwIdEmu = nullptr;

HwIdEmu::HwIdEmu(Logger* logger)
    : m_logger(logger)
    , m_enabled(false)
    , m_initialized(false)
    , m_volumeInfo{ L"SYSTEM", 0x12345678 }
{
}

HwIdEmu::~HwIdEmu()
{
    Shutdown();
    g_hwIdEmu = nullptr;
}

bool HwIdEmu::Initialize()
{
    if (m_initialized) return true;
    if (!m_enabled) {
        m_initialized = true;
        return true;
    }

    g_hwIdEmu = this;
    m_initialized = true;
    m_logger->Trace(LOG_INFO, "HwIdEmu: initialized with %zu disk(s), volume=0x%08X",
        m_disks.size(), m_volumeInfo.serialNumber);
    return true;
}

void HwIdEmu::Shutdown()
{
    if (!m_initialized) return;
    g_hwIdEmu = nullptr;
    m_initialized = false;
}

void HwIdEmu::LoadFromConfig(ConfigParser* config)
{
    if (!config) return;

    m_enabled = config->GetBool("hwid_spoofing", "enabled", true);

    // Storage disks
    m_disks.clear();
    for (uint32_t i = 0; ; i++) {
        std::string idx = std::to_string(i);
        std::string modelKey = "disk" + idx + "_model";
        std::string serialKey = "disk" + idx + "_serial";
        std::string sizeKey = "disk" + idx + "_size";

        std::string model = config->GetString("storage", modelKey, "");
        if (model.empty()) break;

        DiskSpoofInfo disk;
        std::string modelStr = config->GetString("storage", modelKey, "Generic SSD");
        std::string defaultSerial = "SYMBIOTE_" + std::to_string(0x10000000 + i * 0x100);
        std::string serialStr = config->GetString("storage", serialKey, defaultSerial);
        disk.model.assign(modelStr.begin(), modelStr.end());
        disk.serial.assign(serialStr.begin(), serialStr.end());
        disk.sizeBytes = config->GetUint64("storage", sizeKey, 500105249280ULL);
        m_disks.push_back(disk);
    }

    // Volume serial from [storage] or generate
    uint32_t volSerial = (uint32_t)config->GetUint64("storage", "volume_serial", 0);
    if (volSerial == 0) {
        volSerial = 0x12345678;
    }
    std::string volLabel = config->GetString("storage", "volume_label", "SYSTEM");
    m_volumeInfo.serialNumber = volSerial;
    m_volumeInfo.label.assign(volLabel.begin(), volLabel.end());

    // System identifiers (shared with ProcessEmu's [hardware] section)
    auto readWs = [&](const std::string& section, const std::string& key, const char* def) -> std::wstring {
        std::string val = config->GetString(section, key, def ? std::string(def) : "");
        return std::wstring(val.begin(), val.end());
    };

    m_biosVendor = readWs("hardware", "bios_vendor", "Dell Inc.");
    m_biosVersion = readWs("hardware", "bios_version", "A03");
    m_systemManufacturer = readWs("hardware", "manufacturer", "Dell Inc.");
    m_systemProduct = readWs("hardware", "product", "Inspiron 3542");
    m_systemSerial = readWs("hardware", "serial", "SN0123456789");
    m_baseboardSerial = readWs("hardware", "baseboard_serial", "MB0123456789");
    m_chassisSerial = readWs("hardware", "chassis_serial", "CH0123456789");

    m_logger->Trace(LOG_INFO, "HwIdEmu: loaded %zu disk(s) from config, volume=0x%08X",
        m_disks.size(), m_volumeInfo.serialNumber);
}

const DiskSpoofInfo* HwIdEmu::GetDisk(uint32_t index) const
{
    if (index >= m_disks.size()) return nullptr;
    return &m_disks[index];
}

std::wstring HwIdEmu::MakeFakeSerial(uint32_t index) const
{
    std::wstringstream ss;
    ss << L"SYMBIOTE_";
    ss << std::hex << std::uppercase << std::setw(8) << std::setfill(L'0') << (0x10000000 + index * 0x100);
    return ss.str();
}

bool HwIdEmu::HandleStorageQueryProperty(void* outputBuffer, uint32_t outputLength, uint32_t diskIndex, uint64_t* result)
{
    if (!outputBuffer || outputLength < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        if (result) *result = (uint64_t)STATUS_BUFFER_TOO_SMALL;
        return true;
    }

    const DiskSpoofInfo* disk = GetDisk(diskIndex);
    if (!disk) {
        // Return generic descriptor
        STORAGE_DEVICE_DESCRIPTOR desc;
        memset(&desc, 0, sizeof(desc));
        desc.Version = sizeof(STORAGE_DEVICE_DESCRIPTOR);
        desc.Size = sizeof(STORAGE_DEVICE_DESCRIPTOR);
        desc.DeviceType = FILE_DEVICE_DISK;
        desc.DeviceTypeModifier = 0;
        desc.CommandQueueing = TRUE;
        desc.VendorIdOffset = 0;
        desc.ProductIdOffset = 0;
        desc.ProductRevisionOffset = 0;
        desc.SerialNumberOffset = 0;
        desc.BusType = BusTypeSata;
        memcpy(outputBuffer, &desc, sizeof(desc));
        if (result) *result = (uint64_t)STATUS_SUCCESS;
        return true;
    }

    // Build descriptor with vendor/product/serial strings appended
    // Layout: STORAGE_DEVICE_DESCRIPTOR + vendor + product + revision + serial
    auto ws2s = [](const std::wstring& ws) -> std::string {
        int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), NULL, 0, NULL, NULL);
        std::string s((size_t)len, '\0');
        WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &s[0], len, NULL, NULL);
        return s;
    };

    std::string vendorStr = "Symbiote ";
    std::string productStr = ws2s(disk->model);
    std::string revisionStr = "1.0";
    std::string serialStr = ws2s(disk->serial);

    uint32_t totalLen = sizeof(STORAGE_DEVICE_DESCRIPTOR);
    uint32_t vendorOff = totalLen;
    totalLen += (uint32_t)vendorStr.length() + 1;
    uint32_t productOff = totalLen;
    totalLen += (uint32_t)productStr.length() + 1;
    uint32_t revisionOff = totalLen;
    totalLen += (uint32_t)revisionStr.length() + 1;
    uint32_t serialOff = totalLen;
    totalLen += (uint32_t)serialStr.length() + 1;

    if (outputLength < totalLen) {
        // Return minimal descriptor with size
        STORAGE_DEVICE_DESCRIPTOR desc;
        memset(&desc, 0, sizeof(desc));
        desc.Version = sizeof(STORAGE_DEVICE_DESCRIPTOR);
        desc.Size = totalLen;
        desc.DeviceType = FILE_DEVICE_DISK;
        desc.BusType = BusTypeSata;
        memcpy(outputBuffer, &desc, sizeof(desc));
        if (result) *result = (uint64_t)STATUS_BUFFER_TOO_SMALL;
        // Still write required size
        if (outputLength >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
            ((STORAGE_DEVICE_DESCRIPTOR*)outputBuffer)->Size = totalLen;
        }
        return true;
    }

    STORAGE_DEVICE_DESCRIPTOR desc;
    memset(&desc, 0, sizeof(desc));
    desc.Version = sizeof(STORAGE_DEVICE_DESCRIPTOR);
    desc.Size = totalLen;
    desc.DeviceType = FILE_DEVICE_DISK;
    desc.DeviceTypeModifier = 0;
    desc.CommandQueueing = TRUE;
    desc.VendorIdOffset = vendorOff;
    desc.ProductIdOffset = productOff;
    desc.ProductRevisionOffset = revisionOff;
    desc.SerialNumberOffset = serialOff;
    desc.BusType = BusTypeSata;
    desc.RemovableMedia = FALSE;

    memcpy(outputBuffer, &desc, sizeof(desc));
    char* buf = (char*)outputBuffer;
    memcpy(buf + vendorOff, vendorStr.c_str(), vendorStr.length() + 1);
    memcpy(buf + productOff, productStr.c_str(), productStr.length() + 1);
    memcpy(buf + revisionOff, revisionStr.c_str(), revisionStr.length() + 1);
    memcpy(buf + serialOff, serialStr.c_str(), serialStr.length() + 1);

    if (result) *result = (uint64_t)STATUS_SUCCESS;
    return true;
}

bool HwIdEmu::HandleAtaPassThrough(void* inputBuffer, uint32_t inputLength, void* outputBuffer, uint32_t outputLength, uint64_t* result)
{
    (void)inputBuffer;
    (void)inputLength;
    // Return fake identity data for ATA IDENTIFY DEVICE
    if (outputBuffer && outputLength >= 512) {
        // Return minimal ATA IDENTIFY data with spoofed serial
        memset(outputBuffer, 0, outputLength);
        uint16_t* words = (uint16_t*)outputBuffer;
        words[0] = 0x0040; // general config
        words[10] = 0x1234; // serial (first 4 chars)
        words[23] = 0x5678; // firmware revision
        words[27] = 0x9ABC; // model number
        if (result) *result = (uint64_t)STATUS_SUCCESS;
    } else {
        if (result) *result = (uint64_t)STATUS_BUFFER_TOO_SMALL;
    }
    return true;
}

bool HwIdEmu::HandleNvmePassThrough(void* inputBuffer, uint32_t inputLength, void* outputBuffer, uint32_t outputLength, uint64_t* result)
{
    (void)inputBuffer;
    (void)inputLength;
    // Return fake NVMe identify data
    if (outputBuffer && outputLength >= 4096) {
        memset(outputBuffer, 0, outputLength);
        // Serial number at offset 4 (20 bytes)
        memcpy((char*)outputBuffer + 4, "SYM2024NVME1234567", 20);
        // Model number at offset 24 (40 bytes)
        memcpy((char*)outputBuffer + 24, "Symbiote NVMe SSD", 20);
        // IEEE at offset 64 (6 bytes)
        memcpy((char*)outputBuffer + 64, "\x00\x1A\x2B\x3C\x4D\x5E", 6);
        if (result) *result = (uint64_t)STATUS_SUCCESS;
    } else {
        if (result) *result = (uint64_t)STATUS_BUFFER_TOO_SMALL;
    }
    return true;
}

bool HwIdEmu::HandleSmartQuery(void* outputBuffer, uint32_t outputLength, uint64_t* result)
{
    if (!outputBuffer || outputLength < 2) {
        if (result) *result = (uint64_t)STATUS_BUFFER_TOO_SMALL;
        return true;
    }
    // Return clean S.M.A.R.T status
    memset(outputBuffer, 0, outputLength);
    if (outputLength >= 2) {
        uint8_t* buf = (uint8_t*)outputBuffer;
        buf[0] = 0; // threshold exceeded = NO
    }
    if (result) *result = (uint64_t)STATUS_SUCCESS;
    return true;
}

bool HwIdEmu::HandleVolumeInformation(uint64_t buffer, uint32_t length, uint64_t* result)
{
    // FileFsVolumeInformation class
    typedef struct _FILE_FS_VOLUME_INFORMATION {
        LARGE_INTEGER VolumeCreationTime;
        ULONG VolumeSerialNumber;
        ULONG VolumeLabelLength;
        BOOLEAN SupportsObjects;
        WCHAR VolumeLabel[1];
    } FILE_FS_VOLUME_INFORMATION;

    uint32_t needed = FIELD_OFFSET(FILE_FS_VOLUME_INFORMATION, VolumeLabel) +
                      (uint32_t)(m_volumeInfo.label.length() * sizeof(wchar_t));
    if (length < needed) {
        if (result) *result = (uint64_t)STATUS_BUFFER_TOO_SMALL;
        return true;
    }

    FILE_FS_VOLUME_INFORMATION* info = (FILE_FS_VOLUME_INFORMATION*)(uintptr_t)buffer;
    info->VolumeCreationTime.QuadPart = 0x01D8000000000000ULL;
    info->VolumeSerialNumber = m_volumeInfo.serialNumber;
    info->VolumeLabelLength = (ULONG)(m_volumeInfo.label.length() * sizeof(wchar_t));
    info->SupportsObjects = TRUE;
    memcpy(info->VolumeLabel, m_volumeInfo.label.c_str(), info->VolumeLabelLength);

    m_logger->Trace(LOG_EMU, "HwIdEmu: spoofed volume serial=0x%08X label=%ls",
        m_volumeInfo.serialNumber, m_volumeInfo.label.c_str());
    if (result) *result = (uint64_t)STATUS_SUCCESS;
    return true;
}
