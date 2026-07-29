#include "QemuTableGen.h"
#include <cstring>
#include <algorithm>

QemuTableGen::QemuTableGen() : m_initialized(false) {
    memset(&m_config, 0, sizeof(m_config));
}

QemuTableGen::~QemuTableGen() {}

bool QemuTableGen::Init(const QemuTableConfig& config) {
    m_config = config;
    m_initialized = true;
    return true;
}

void QemuTableGen::ComputeChecksum(AcpiHeader* header) {
    uint8_t sum = 0;
    uint8_t* bytes = (uint8_t*)header;
    for (uint32_t i = 0; i < header->length; i++) {
        sum += bytes[i];
    }
    header->checksum = (uint8_t)(0x100 - sum);
}

bool QemuTableGen::GenerateAcpiTables(
    std::vector<uint8_t>& outRsdp,
    std::vector<uint8_t>& outRsdt,
    std::vector<uint8_t>& outXsdt,
    std::vector<uint8_t>& outFadt,
    std::vector<uint8_t>& outFacs,
    std::vector<uint8_t>& outDsdt,
    std::vector<uint8_t>& outMcfg,
    std::vector<uint8_t>& outHpet,
    std::vector<uint8_t>& outDmar)
{
    if (!m_initialized) return false;

    const char* oemId = m_config.systemManufacturer;
    const char* oemTableId = "GENJUTSU";
    const char* oemRev = "\1\0\0\0";
    const char* creatorId = "GJTS";
    const char* creatorRev = "\1\0\0\0";

    // --- RSDP (Root System Description Pointer) ---
    struct Rsdp {
        char     signature[8];     // "RSD PTR "
        uint8_t  checksum;
        char     oemId[6];
        uint8_t  revision;
        uint32_t rsdtAddress;
        uint32_t length;
        uint64_t xsdtAddress;
        uint8_t  extendedChecksum;
        uint8_t  reserved[3];
    } rsdp = {};
    memcpy(rsdp.signature, "RSD PTR ", 8);
    memcpy(rsdp.oemId, oemId, 6);
    rsdp.revision = 2;
    rsdp.rsdtAddress = (uint32_t)(GetAcpiBasePhys());
    rsdp.length = sizeof(Rsdp);
    rsdp.xsdtAddress = (GetAcpiBasePhys() + 0x1000);
    // Compute primary checksum
    rsdp.checksum = 0;
    uint8_t sum = 0;
    for (size_t i = 0; i < 20; i++) sum += ((uint8_t*)&rsdp)[i];
    rsdp.checksum = (uint8_t)(0x100 - sum);
    // Extended checksum
    rsdp.extendedChecksum = 0;
    sum = 0;
    for (size_t i = 0; i < sizeof(Rsdp); i++) sum += ((uint8_t*)&rsdp)[i];
    rsdp.extendedChecksum = (uint8_t)(0x100 - sum);
    outRsdp.resize(sizeof(Rsdp));
    memcpy(outRsdp.data(), &rsdp, sizeof(Rsdp));

    // --- FADT (Fixed ACPI Description Table) ---
    struct Facp {
        AcpiHeader header;
        uint32_t facsAddr;
        uint32_t dsdtAddr;
        uint8_t  model;
        uint8_t  reserved1;
        uint16_t sciInt;
        uint32_t smiCmd;
        uint8_t  acpiEnabled;
        uint8_t  acpiDisabled;
        uint8_t  s4biosReq;
        uint8_t  pStateCnt;
        uint32_t pm1aEvtBlk;
        uint32_t pm1bEvtBlk;
        uint32_t pm1aCntBlk;
        uint32_t pm1bCntBlk;
        uint32_t pm2CntBlk;
        uint32_t pmTmrBlk;
        uint32_t gpe0Blk;
        uint32_t gpe1Blk;
        uint8_t  pm1EvtLen;
        uint8_t  pm1CntLen;
        uint8_t  pm2CntLen;
        uint8_t  pmTmrLen;
        uint8_t  gpe0BlkLen;
        uint8_t  gpe1BlkLen;
        uint8_t  gpe1Base;
        uint8_t  cstCnt;
        uint16_t pLatency;
        uint16_t bLatency;
        uint16_t pWidth;
        uint16_t bWidth;
        uint16_t pParam;
        uint16_t bParam;
        uint8_t  hpetCaps;
        uint8_t  iortCaps;
        uint16_t prefWidth;
        uint64_t addrFadtBase;
        uint64_t addrXsdtBase;
    } __attribute__((packed)) facp = {};
    memcpy(facp.header.signature, "FACP", 4);
    facp.header.length = sizeof(Facp);
    facp.header.revision = 6;
    memcpy(facp.header.oemId, oemId, 6);
    memcpy(facp.header.oemTableId, oemTableId, 8);
    memcpy(facp.header.oemRevision, oemRev, 4);
    memcpy(facp.header.creatorId, creatorId, 4);
    memcpy(facp.header.creatorRev, creatorRev, 4);
    facp.facsAddr = (uint32_t)(GetAcpiBasePhys() + 0x2000);
    facp.dsdtAddr = (uint32_t)(GetAcpiBasePhys() + 0x3000);
    facp.sciInt = 0x9;
    facp.pm1aEvtBlk = 0x400;
    facp.pm1bEvtBlk = 0;
    facp.pm1aCntBlk = 0x404;
    facp.pmTmrBlk = m_config.pmTimerPort ? m_config.pmTimerPort : 0x408;
    facp.pmTmrLen = 4;
    facp.gpe0Blk = 0x420;
    facp.gpe0BlkLen = 4;
    ComputeChecksum(&facp.header);
    outFadt.resize(sizeof(Facp));
    memcpy(outFadt.data(), &facp, sizeof(Facp));

    // --- FACS (Firmware ACPI Control Structure) ---
    struct Facs {
        char     signature[4];
        uint32_t length;
        uint32_t hwSig;
        uint32_t wakeVector;
        uint32_t globalLock;
        uint32_t flags;
        uint64_t xWakeVector;
        uint8_t  version;
        uint8_t  reserved[31];
    } facs = {};
    memcpy(facs.signature, "FACS", 4);
    facs.length = sizeof(Facs);
    facs.flags = 0;
    outFacs.resize(sizeof(Facs));
    memcpy(outFacs.data(), &facs, sizeof(Facs));

    // --- DSDT (Differentiated System Description Table) ---
    // Minimal DSDT with root scope + processor definitions
    struct DsdtTemplate {
        AcpiHeader header;
        uint8_t    defScope[5];    // DefinitionBlock scope
        uint8_t    rootScope[6];   // Scope(\)
        uint8_t    processor[12];  // Processor(CPU0,...)
        uint8_t    endScope;
        uint8_t    endScope2;
    } dsdt = {};
    memcpy(dsdt.header.signature, "DSDT", 4);
    dsdt.header.length = sizeof(DsdtTemplate);
    dsdt.header.revision = 2;
    memcpy(dsdt.header.oemId, oemId, 6);
    memcpy(dsdt.header.oemTableId, oemTableId, 8);
    memcpy(dsdt.header.oemRevision, oemRev, 4);
    memcpy(dsdt.header.creatorId, creatorId, 4);
    memcpy(dsdt.header.creatorRev, creatorRev, 4);
    // Root scope: Scope(\)
    dsdt.rootScope[0] = 0x10;  // Scope opcode
    dsdt.rootScope[1] = 0x40;  // PkgLength (future)
    dsdt.rootScope[2] = 0x5C;  // NameString: \
    dsdt.rootScope[3] = 0x00;  // TermList
    dsdt.endScope = 0x79;      // EndTag
    dsdt.endScope2 = 0x00;
    ComputeChecksum(&dsdt.header);
    outDsdt.resize(sizeof(DsdtTemplate));
    memcpy(outDsdt.data(), &dsdt, sizeof(DsdtTemplate));

    // --- HPET table ---
    struct HpetTable {
        AcpiHeader header;
        uint32_t   id;
        uint32_t   baseAddrLo;
        uint32_t   baseAddrHi;
        uint16_t   seqNum;
        uint16_t   minTick;
        uint8_t    pageProtect;
    } __attribute__((packed)) hpet = {};
    memcpy(hpet.header.signature, "HPET", 4);
    hpet.header.length = sizeof(HpetTable);
    hpet.header.revision = 1;
    memcpy(hpet.header.oemId, oemId, 6);
    memcpy(hpet.header.oemTableId, oemTableId, 8);
    memcpy(hpet.header.oemRevision, oemRev, 4);
    memcpy(hpet.header.creatorId, creatorId, 4);
    memcpy(hpet.header.creatorRev, creatorRev, 4);
    hpet.id = 0x8086A201;  // Intel + legacy replacement timer
    hpet.baseAddrLo = 0xFED00000;
    hpet.seqNum = 0;
    hpet.minTick = 4096;
    hpet.pageProtect = 0;
    ComputeChecksum(&hpet.header);
    outHpet.resize(sizeof(HpetTable));
    memcpy(outHpet.data(), &hpet, sizeof(HpetTable));

    // --- MCFG (PCI Express Memory Mapped Config) ---
    struct McfgEntry {
        uint64_t baseAddress;
        uint16_t segmentGroup;
        uint8_t  busStart;
        uint8_t  busEnd;
        uint32_t reserved;
    };
    struct McfgTable {
        AcpiHeader header;
        uint64_t   reserved;
        McfgEntry  entry;
    } __attribute__((packed)) mcfg = {};
    memcpy(mcfg.header.signature, "MCFG", 4);
    mcfg.header.length = sizeof(McfgTable);
    mcfg.header.revision = 1;
    memcpy(mcfg.header.oemId, oemId, 6);
    memcpy(mcfg.header.oemTableId, oemTableId, 8);
    memcpy(mcfg.header.oemRevision, oemRev, 4);
    memcpy(mcfg.header.creatorId, creatorId, 4);
    memcpy(mcfg.header.creatorRev, creatorRev, 4);
    mcfg.entry.baseAddress = m_config.pcieEcBase ? m_config.pcieEcBase : 0xE0000000ULL;
    mcfg.entry.segmentGroup = m_config.pcieSegmentGroup;
    mcfg.entry.busStart = 0;
    mcfg.entry.busEnd = 0xFF;
    ComputeChecksum(&mcfg.header);
    outMcfg.resize(sizeof(McfgTable));
    memcpy(outMcfg.data(), &mcfg, sizeof(McfgTable));

    // RSDT — 32-bit table
    struct RsdtTable {
        AcpiHeader header;
        uint32_t   entry[8];  // Pointers to other tables
    } rsdt = {};
    memcpy(rsdt.header.signature, "RSDT", 4);
    rsdt.header.length = sizeof(RsdtTable);
    rsdt.header.revision = 1;
    memcpy(rsdt.header.oemId, oemId, 6);
    memcpy(rsdt.header.oemTableId, oemTableId, 8);
    memcpy(rsdt.header.oemRevision, oemRev, 4);
    memcpy(rsdt.header.creatorId, creatorId, 4);
    memcpy(rsdt.header.creatorRev, creatorRev, 4);
    uint32_t baseAcpi = (uint32_t)GetAcpiBasePhys();
    rsdt.entry[0] = baseAcpi + 0x1000;  // FADT
    rsdt.entry[1] = baseAcpi + 0x3000;  // DSDT
    rsdt.entry[2] = baseAcpi + 0x4000;  // HPET
    rsdt.entry[3] = baseAcpi + 0x5000;  // MCFG
    ComputeChecksum(&rsdt.header);
    outRsdt.resize(sizeof(RsdtTable));
    memcpy(outRsdt.data(), &rsdt, sizeof(RsdtTable));

    // XSDT — 64-bit table
    struct XsdtTable {
        AcpiHeader header;
        uint64_t   entry[8];
    } xsdt = {};
    memcpy(xsdt.header.signature, "XSDT", 4);
    xsdt.header.length = sizeof(XsdtTable);
    xsdt.header.revision = 1;
    memcpy(xsdt.header.oemId, oemId, 6);
    memcpy(xsdt.header.oemTableId, oemTableId, 8);
    memcpy(xsdt.header.oemRevision, oemRev, 4);
    memcpy(xsdt.header.creatorId, creatorId, 4);
    memcpy(xsdt.header.creatorRev, creatorRev, 4);
    xsdt.entry[0] = baseAcpi + 0x1000;
    xsdt.entry[1] = baseAcpi + 0x3000;
    xsdt.entry[2] = baseAcpi + 0x4000;
    xsdt.entry[3] = baseAcpi + 0x5000;
    ComputeChecksum(&xsdt.header);
    outXsdt.resize(sizeof(XsdtTable));
    memcpy(outXsdt.data(), &xsdt, sizeof(XsdtTable));

    // DMAR (VT-d)
    if (m_config.enableDmar) {
        struct DmarTable {
            AcpiHeader header;
            uint8_t    hostAddrWidth;
            uint8_t    flags;
            uint8_t    reserved[10];
        } dmar = {};
        memcpy(dmar.header.signature, "DMAR", 4);
        dmar.header.length = sizeof(DmarTable);
        dmar.header.revision = 1;
        memcpy(dmar.header.oemId, oemId, 6);
        memcpy(dmar.header.oemTableId, oemTableId, 8);
        memcpy(dmar.header.oemRevision, oemRev, 4);
        memcpy(dmar.header.creatorId, creatorId, 4);
        memcpy(dmar.header.creatorRev, creatorRev, 4);
        dmar.hostAddrWidth = 48;
        dmar.flags = 0;
        ComputeChecksum(&dmar.header);
        outDmar.resize(sizeof(DmarTable));
        memcpy(outDmar.data(), &dmar, sizeof(DmarTable));
    }

    return true;
}

bool QemuTableGen::GenerateSmbiosTables(std::vector<uint8_t>& outTables,
                                         std::vector<uint8_t>& outEntryPoint) {
    if (!m_initialized) return false;

    // SMBIOS entry point structure
#pragma pack(push, 1)
    struct SmbiosEntry {
        char     anchor[4];        // "_SM_"
        uint8_t  checksum;
        uint8_t  length;
        uint8_t  majorVer;
        uint8_t  minorVer;
        uint16_t maxStructSize;
        uint8_t  revision;
        uint8_t  formattedArea[5];
        char     intermediateAnchor[5]; // "_DMI_"
        uint8_t  intermediateChecksum;
        uint16_t tableLength;
        uint32_t tableAddress;
        uint16_t tableCount;
        uint8_t  bcdRevision;
    };
#pragma pack(pop)

    // Build SMBIOS tables
    // Type 0: BIOS Information
    struct SmbiosType0 {
        uint8_t  type;
        uint8_t  length;
        uint16_t handle;
        uint8_t  vendor;
        uint8_t  version;
        uint8_t  releaseDate;
        uint8_t  biosSegment;
        uint8_t  releaseMajor;
        uint8_t  releaseMinor;
        uint8_t  biosChar1[8];
    } type0 = {};
    type0.type = 0;
    type0.length = sizeof(SmbiosType0);
    type0.handle = 0;
    type0.vendor = 1; // string index
    type0.version = 2;
    type0.releaseDate = 3;

    // Type 1: System Information
    struct SmbiosType1 {
        uint8_t  type;
        uint8_t  length;
        uint16_t handle;
        uint8_t  manufacturer;
        uint8_t  productName;
        uint8_t  version;
        uint8_t  serial;
        uint8_t  uuid[16];
        uint8_t  wakeupType;
        uint8_t  sku;
        uint8_t  family;
    } type1 = {};
    type1.type = 1;
    type1.length = sizeof(SmbiosType1);
    type1.handle = 1;
    type1.manufacturer = 1;
    type1.productName = 2;
    type1.serial = 3;
    type1.wakeupType = 0x06; // Power Switch

    // Type 4: Processor Information
    struct SmbiosType4 {
        uint8_t  type;
        uint8_t  length;
        uint16_t handle;
        uint8_t  socket;
        uint8_t  processorType;
        uint8_t  processorFamily;
        uint8_t  manufacturer;
        uint64_t cpuid[2];
        uint8_t  version;
        uint8_t  voltage;
        uint16_t externalClock;
        uint16_t maxSpeed;
        uint16_t currentSpeed;
    } type4 = {};
    type4.type = 4;
    type4.length = sizeof(SmbiosType4);
    type4.handle = 4;
    type4.socket = 1;
    type4.processorType = 3; // Central Processor
    type4.processorFamily = (uint8_t)(m_config.cpuSignature >> 8);
    type4.manufacturer = 2;

    // Pack strings: vendor\0version\0date\0\0
    char strings[256] = {};
    size_t off = 0;
    auto addString = [&](const char* s) {
        size_t len = strlen(s) + 1;
        memcpy(strings + off, s, len);
        off += len;
    };
    addString(m_config.biosVendor);
    addString(m_config.biosVersion);
    addString(m_config.biosDate);
    strings[off++] = '\0'; // terminator

    // Type 1 strings
    char t1Strings[256] = {};
    off = 0;
    addString(m_config.systemManufacturer);
    addString(m_config.systemProductName);
    addString(m_config.systemSerial);
    t1Strings[off++] = '\0';

    // Type 4 strings
    char t4Strings[256] = {};
    off = 0;
    addString("CPU Socket");
    addString(m_config.cpuVendorString);
    t4Strings[off++] = '\0';

    // Assemble all tables + strings
    outTables.clear();
    auto append = [&](const void* data, size_t len) {
        size_t old = outTables.size();
        outTables.resize(old + len);
        memcpy(outTables.data() + old, data, len);
    };
    append(&type0, sizeof(type0));
    append(strings, strlen(strings) + 2);
    append(&type1, sizeof(type1));
    append(t1Strings, strlen(t1Strings) + 2);
    append(&type4, sizeof(type4));
    append(t4Strings, strlen(t4Strings) + 2);

    // Entry point
    SmbiosEntry ep = {};
    memcpy(ep.anchor, "_SM_", 4);
    ep.length = sizeof(SmbiosEntry);
    ep.majorVer = 3;
    ep.minorVer = 4;
    ep.maxStructSize = 0x100;
    ep.revision = 0;
    memset(ep.formattedArea, 0, 5);
    memcpy(ep.intermediateAnchor, "_DMI_", 5);
    ep.tableLength = (uint16_t)outTables.size();
    ep.tableAddress = 0x7FE00000; // FSEG
    ep.tableCount = 3;
    ep.bcdRevision = 0x34;

    // Compute checksums
    ep.checksum = 0;
    uint8_t sum = 0;
    for (size_t i = 0; i < 0x10; i++) sum += ((uint8_t*)&ep)[i];
    ep.checksum = (uint8_t)(0x100 - sum);

    ep.intermediateChecksum = 0;
    sum = 0;
    for (size_t i = 0x10; i < sizeof(SmbiosEntry); i++) sum += ((uint8_t*)&ep)[i];
    ep.intermediateChecksum = (uint8_t)(0x100 - sum);

    outEntryPoint.resize(sizeof(SmbiosEntry));
    memcpy(outEntryPoint.data(), &ep, sizeof(SmbiosEntry));
    return true;
}

bool QemuTableGen::BuildFirmwareRegion(std::vector<uint8_t>& outRegion) {
    std::vector<uint8_t> rsdp, rsdt, xsdt, fadt, facs, dsdt, mcfg, hpet, dmar;
    if (!GenerateAcpiTables(rsdp, rsdt, xsdt, fadt, facs, dsdt, mcfg, hpet, dmar))
        return false;

    // Lay out at ACPI base with 0x1000 alignment
    uint64_t base = GetAcpiBasePhys();
    size_t offset = 0;
    auto place = [&](std::vector<uint8_t>& tbl, const char* name, uint64_t align) {
        // Align
        if (offset % align) offset += align - (offset % align);
        offset += tbl.size();
    };
    place(rsdp, "RSDP", 16);
    place(rsdt, "RSDT", 16);
    place(xsdt, "XSDT", 16);
    place(fadt, "FADT", 16);
    place(facs, "FACS", 64);
    place(dsdt, "DSDT", 16);
    place(mcfg, "MCFG", 16);
    place(hpet, "HPET", 16);
    place(dmar, "DMAR", 16);

    // Build contiguous blob
    outRegion.resize(offset + 0x100000);
    memset(outRegion.data(), 0, outRegion.size());
    offset = 0;
    offset += (offset % 16) ? (16 - offset % 16) : 0;
    memcpy(outRegion.data() + offset, rsdp.data(), rsdp.size());
    offset = 0x1000;
    memcpy(outRegion.data() + offset, fadt.data(), fadt.size());
    offset = 0x2000;
    memcpy(outRegion.data() + offset, facs.data(), facs.size());
    offset = 0x3000;
    memcpy(outRegion.data() + offset, dsdt.data(), dsdt.size());
    offset = 0x4000;
    memcpy(outRegion.data() + offset, hpet.data(), hpet.size());
    offset = 0x5000;
    memcpy(outRegion.data() + offset, mcfg.data(), mcfg.size());

    return true;
}

bool QemuTableGen::DeployToPartition(void* partitionHandle) {
    // Stub: walk WHP partition and map firmware GPA range
    return true;
}