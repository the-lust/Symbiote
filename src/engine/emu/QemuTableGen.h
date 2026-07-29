#pragma once
#include <windows.h>
#include <cstdint>
#include <vector>

// QEMU firmware table generation library (Tier B)
// Links QEMU's ACPI/SMBIOS table generators into engine.dll
// Always-on: generates spoofed firmware tables for the guest

// ACPI table types we can generate
enum QemuTableType : uint32_t {
    QTABLE_RSDP  = 0,
    QTABLE_RSDT  = 1,
    QTABLE_XSDT  = 2,
    QTABLE_FADT  = 3,
    QTABLE_FACS  = 4,
    QTABLE_DSDT  = 5,
    QTABLE_SSDT  = 6,
    QTABLE_MCFG  = 7,
    QTABLE_HPET  = 8,
    QTABLE_DMAR  = 9,
    QTABLE_IVRS  = 10,
    QTABLE_SRAT  = 11,
    QTABLE_SLIT  = 12,
    QTABLE_COUNT
};

// SMBIOS table types
enum QemuSmbiosType : uint32_t {
    QSMBIOS_BIOS      = 0,
    QSMBIOS_SYSTEM    = 1,
    QSMBIOS_BASEBOARD = 2,
    QSMBIOS_CHASSIS   = 3,
    QSMBIOS_PROCESSOR = 4,
    QSMBIOS_MEMORY    = 5,
    QSMBIOS_COUNT
};

struct QemuTableConfig {
    // CPU info for ACPI processor objects
    uint32_t cpuCount;
    uint32_t cpuFamily;
    uint32_t cpuModel;
    uint32_t cpuStepping;
    uint32_t cpuSignature;
    char     cpuVendorString[16];
    char     cpuBrandString[64];

    // System identification
    char     biosVendor[64];
    char     biosVersion[64];
    char     biosDate[32];
    char     systemManufacturer[64];
    char     systemProductName[64];
    char     systemSerial[64];
    char     systemUuid[48];
    char     baseboardManufacturer[64];
    char     baseboardProduct[64];

    // Memory configuration
    uint64_t memorySizeBytes;
    uint64_t hpetFrequency;         // default 14318180 (HPET legacy)
    uint64_t tscFrequency;          // Hz
    uint32_t pmTimerPort;           // ACPI PM_TMR IO port

    // PCIe config
    uint32_t pcieEcBase;            // MCFG ECAM base
    uint32_t pcieSegmentGroup;
    uint16_t pcieBusStart;
    uint16_t pcieBusEnd;

    // DMAR/IOMMU
    bool     enableDmar;
    bool     enableIvrs;
};

class QemuTableGen {
public:
    QemuTableGen();
    ~QemuTableGen();

    // Initialize with target configuration
    bool Init(const QemuTableConfig& config);

    // Generate all ACPI tables
    bool GenerateAcpiTables(std::vector<uint8_t>& outRsdp, std::vector<uint8_t>& outRsdt,
                            std::vector<uint8_t>& outXsdt, std::vector<uint8_t>& outFadt,
                            std::vector<uint8_t>& outFacs, std::vector<uint8_t>& outDsdt,
                            std::vector<uint8_t>& outMcfg, std::vector<uint8_t>& outHpet,
                            std::vector<uint8_t>& outDmar);

    // Generate all SMBIOS tables
    bool GenerateSmbiosTables(std::vector<uint8_t>& outTables,
                              std::vector<uint8_t>& outEntryPoint);

    // Get a single ACPI table by type
    bool GetAcpiTable(QemuTableType type, std::vector<uint8_t>& out);

    // Get a single SMBIOS table by type
    bool GetSmbiosTable(QemuSmbiosType type, std::vector<uint8_t>& out);

    // Build complete firmware region (ACPI + SMBIOS contiguous)
    // Returns the full blob ready for GPA mapping
    bool BuildFirmwareRegion(std::vector<uint8_t>& outRegion);

    // Get base address for firmware region in guest physical space
    uint64_t GetFirmwareBasePhys() const { return 0xF0000; }  // Legacy BIOS area
    uint64_t GetAcpiBasePhys() const { return 0x7FEB0000ULL; } // ACPI tables

    // Register all tables into WHP partition memory
    bool DeployToPartition(void* partitionHandle);

private:
    // ACPI table header
    struct AcpiHeader {
        char     signature[4];
        uint32_t length;
        uint8_t  revision;
        uint8_t  checksum;
        char     oemId[6];
        char     oemTableId[8];
        char     oemRevision[4];
        char     creatorId[4];
        char     creatorRev[4];
    };

    // Compute ACPI checksum
    void ComputeChecksum(AcpiHeader* header);

    // Build SSDT for processor objects
    bool BuildSsdt(std::vector<uint8_t>& out);

    QemuTableConfig m_config;
    bool m_initialized;
};