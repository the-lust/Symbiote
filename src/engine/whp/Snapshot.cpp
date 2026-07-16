#include "Snapshot.h"
#include "Logger.h"
#include "Partition.h"
#include "CpuidHandler.h"
#include "RdtscHandler.h"
#include "MsrHandler.h"
#include "EptExecHook.h"
#include <fstream>
#include <vector>
#include <cstring>
#include <algorithm>

Snapshot::Snapshot(Logger* logger)
    : m_logger(logger)
{
}

Snapshot::~Snapshot()
{
}

// All registers we need to save/restore for full VCPU state
static const WHV_REGISTER_NAME kAllRegisters[] = {
    WHvX64RegisterRax, WHvX64RegisterRcx, WHvX64RegisterRdx,
    WHvX64RegisterRbx, WHvX64RegisterRsp, WHvX64RegisterRbp,
    WHvX64RegisterRsi, WHvX64RegisterRdi, WHvX64RegisterR8,
    WHvX64RegisterR9,  WHvX64RegisterR10, WHvX64RegisterR11,
    WHvX64RegisterR12, WHvX64RegisterR13, WHvX64RegisterR14,
    WHvX64RegisterR15, WHvX64RegisterRip, WHvX64RegisterRflags,

    WHvX64RegisterCr0, WHvX64RegisterCr2, WHvX64RegisterCr3,
    WHvX64RegisterCr4, WHvX64RegisterCr8,

    WHvX64RegisterDr0, WHvX64RegisterDr1, WHvX64RegisterDr2,
    WHvX64RegisterDr3, WHvX64RegisterDr6, WHvX64RegisterDr7,

    WHvX64RegisterCs, WHvX64RegisterDs, WHvX64RegisterEs,
    WHvX64RegisterFs, WHvX64RegisterGs, WHvX64RegisterSs,

    WHvX64RegisterEfer, WHvX64RegisterStar, WHvX64RegisterLstar,
    WHvX64RegisterCstar, WHvX64RegisterSfmask,

    WHvX64RegisterGdtr, WHvX64RegisterIdtr,
    WHvX64RegisterTr, WHvX64RegisterLdtr,
};
static constexpr uint32_t kNumSnapshotRegisters =
    sizeof(kAllRegisters) / sizeof(kAllRegisters[0]);

size_t Snapshot::SaveVcpuRegisters(HANDLE partitionHandle, uint32_t vcpuIndex,
                                   uint8_t* buffer, size_t bufferSize)
{
    std::vector<WHV_REGISTER_VALUE> values(kNumSnapshotRegisters);

    HRESULT hr = WHvGetVirtualProcessorRegisters(
        partitionHandle, vcpuIndex, kAllRegisters,
        kNumSnapshotRegisters, values.data());

    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "Snapshot: WHvGetVirtualProcessorRegisters VCPU %u failed: 0x%08X",
            vcpuIndex, hr);
        return 0;
    }

    // Layout: uint32_t count + count * WHV_REGISTER_VALUE
    size_t needed = sizeof(uint32_t) + kNumSnapshotRegisters * sizeof(WHV_REGISTER_VALUE);
    if (bufferSize < needed) {
        m_logger->Trace(LOG_ERROR, "Snapshot: buffer too small for VCPU %u registers", vcpuIndex);
        return 0;
    }

    uint32_t* countOut = (uint32_t*)buffer;
    *countOut = kNumSnapshotRegisters;

    memcpy(buffer + sizeof(uint32_t), values.data(),
           kNumSnapshotRegisters * sizeof(WHV_REGISTER_VALUE));

    return needed;
}

bool Snapshot::RestoreVcpuRegisters(HANDLE partitionHandle, uint32_t vcpuIndex,
                                    const uint8_t* buffer, size_t dataSize)
{
    if (dataSize < sizeof(uint32_t)) {
        m_logger->Trace(LOG_ERROR, "Snapshot: invalid VCPU register data size");
        return false;
    }

    uint32_t count = *(const uint32_t*)buffer;
    if (count > kNumSnapshotRegisters) {
        m_logger->Trace(LOG_ERROR, "Snapshot: VCPU %u register count %u exceeds max %u",
            vcpuIndex, count, kNumSnapshotRegisters);
        return false;
    }

    size_t expectedSize = sizeof(uint32_t) + count * sizeof(WHV_REGISTER_VALUE);
    if (dataSize < expectedSize) {
        m_logger->Trace(LOG_ERROR, "Snapshot: VCPU %u register data truncated", vcpuIndex);
        return false;
    }

    const WHV_REGISTER_VALUE* values =
        (const WHV_REGISTER_VALUE*)(buffer + sizeof(uint32_t));

    HRESULT hr = WHvSetVirtualProcessorRegisters(
        partitionHandle, vcpuIndex, kAllRegisters, count, values);

    if (FAILED(hr)) {
        m_logger->Trace(LOG_ERROR, "Snapshot: WHvSetVirtualProcessorRegisters VCPU %u failed: 0x%08X",
            vcpuIndex, hr);
        return false;
    }

    return true;
}

// ─── Create ───────────────────────────────────────────────────────────

std::vector<uint8_t> Snapshot::Create(Partition* partition,
                                       CpuidHandler* cpuidHandler,
                                       RdtscHandler* rdtscHandler,
                                       MsrHandler* msrHandler,
                                       EptExecHook* eptExecHook)
{
    (void)cpuidHandler;
    (void)rdtscHandler;
    (void)msrHandler;
    (void)eptExecHook;

    if (!partition) {
        m_logger->Trace(LOG_ERROR, "Snapshot: no partition provided");
        return {};
    }

    HANDLE hPartition = partition->GetHandle();
    if (!hPartition) {
        m_logger->Trace(LOG_ERROR, "Snapshot: invalid partition handle");
        return {};
    }

    // Determine VCPU count
    uint32_t numVcpus = partition->GetVcpuCount();
    if (numVcpus == 0) numVcpus = 1; // At least VCPU 0

    // First pass: calculate total size
    size_t totalSize = sizeof(SnapshotHeader);

    // Per-VCPU register state
    for (uint32_t i = 0; i < numVcpus; i++) {
        totalSize += sizeof(uint32_t) + kNumSnapshotRegisters * sizeof(WHV_REGISTER_VALUE);
    }

    // Memory regions (from partition tracking)
    auto memoryRegions = partition->GetTrackedMemoryRegions();
    totalSize += memoryRegions.size() * (sizeof(MemoryRegionBlock) - 1); // variable length handled below

    // Handler state placeholder (4 bytes for size)
    totalSize += sizeof(uint32_t);

    // Allocate buffer
    std::vector<uint8_t> snapshot(totalSize, 0);

    // Fill header
    SnapshotHeader* header = (SnapshotHeader*)snapshot.data();
    memcpy(header->magic, "SYMBIOTE", 8);
    header->magic[7] = '\0';
    header->version = kSnapshotVersion;
    header->numVcpus = numVcpus;
    header->numMemoryRegions = (uint32_t)memoryRegions.size();
    header->handlerDataSize = 0;
    header->timestamp = 0;
    QueryPerformanceCounter((LARGE_INTEGER*)&header->timestamp);

    size_t offset = sizeof(SnapshotHeader);

    // Save VCPU registers (all VCPUs counted by GetVcpuCount should exist)
    for (uint32_t i = 0; i < numVcpus; i++) {
        size_t written = SaveVcpuRegisters(hPartition, i,
            snapshot.data() + offset, snapshot.size() - offset);
        if (written == 0) return {};
        offset += written;
    }

    // Save memory region metadata (content is not saved — too large for
    // practical snapshot. Restored state will re-map the same virtual
    // addresses. EPT re-mapping ensures guest-visible memory is coherent.)
    for (const auto& region : memoryRegions) {
        if (offset + sizeof(MemoryRegionBlock) - 1 + sizeof(uint64_t) * 2 > snapshot.size())
            break;

        MemoryRegionBlock* block = (MemoryRegionBlock*)(snapshot.data() + offset);
        block->gpa = region.gpa;
        block->size = region.size;
        block->flags = region.flags;
        offset += sizeof(MemoryRegionBlock) - 1; // just the fixed part + content[0]
        offset += sizeof(uint64_t) * 2; // gpa + size
    }

    // Handler data size (placeholder — real serialization is handler-specific)
    *(uint32_t*)(snapshot.data() + offset) = 0;
    offset += sizeof(uint32_t);

    // Shrink to actual size
    snapshot.resize(offset);
    header->numMemoryRegions = (uint32_t)((offset - sizeof(SnapshotHeader) -
        numVcpus * (sizeof(uint32_t) + kNumSnapshotRegisters * sizeof(WHV_REGISTER_VALUE)) -
        sizeof(uint32_t)) / (sizeof(MemoryRegionBlock) - 1 + sizeof(uint64_t) * 2));

    m_logger->Trace(LOG_INFO, "Snapshot: created for %u VCPUs, %u regions, %zu bytes",
        numVcpus, header->numMemoryRegions, snapshot.size());

    return snapshot;
}

// ─── Restore ──────────────────────────────────────────────────────────

bool Snapshot::Restore(const std::vector<uint8_t>& snapshotData,
                       Partition* partition,
                       CpuidHandler* cpuidHandler,
                       RdtscHandler* rdtscHandler,
                       MsrHandler* msrHandler,
                       EptExecHook* eptExecHook)
{
    (void)cpuidHandler;
    (void)rdtscHandler;
    (void)msrHandler;
    (void)eptExecHook;

    if (!ValidateHeader(snapshotData.data(), snapshotData.size())) {
        m_logger->Trace(LOG_ERROR, "Snapshot: restore failed — invalid header");
        return false;
    }

    if (!partition) {
        m_logger->Trace(LOG_ERROR, "Snapshot: no partition for restore");
        return false;
    }

    const SnapshotHeader* header = (const SnapshotHeader*)snapshotData.data();
    size_t offset = sizeof(SnapshotHeader);

    // Restore VCPU registers
    for (uint32_t i = 0; i < header->numVcpus; i++) {
        if (i < partition->GetVcpuCount()) {
            size_t regDataSize = snapshotData.size() - offset;
            if (!RestoreVcpuRegisters(partition->GetHandle(), i,
                                       snapshotData.data() + offset, regDataSize)) {
                m_logger->Trace(LOG_WARNING, "Snapshot: VCPU %u restore failed, continuing", i);
            }
        }

        // Skip VCPU register data regardless
        if (offset + sizeof(uint32_t) <= snapshotData.size()) {
            uint32_t regCount = *(const uint32_t*)(snapshotData.data() + offset);
            offset += sizeof(uint32_t) + regCount * sizeof(WHV_REGISTER_VALUE);
        }
    }

    // Memory regions — skip (EPT state is rebuilt on demand by MapDynamicPage)
    // In a full implementation, we would re-map all regions here.
    offset += header->numMemoryRegions * (sizeof(MemoryRegionBlock) - 1 + sizeof(uint64_t) * 2);

    // Handler data — skip
    if (offset + sizeof(uint32_t) <= snapshotData.size()) {
        uint32_t handlerSize = *(const uint32_t*)(snapshotData.data() + offset);
        offset += sizeof(uint32_t) + handlerSize;
    }

    m_logger->Trace(LOG_INFO, "Snapshot: restored state from %zu-byte snapshot", snapshotData.size());
    return true;
}

// ─── File I/O ─────────────────────────────────────────────────────────

bool Snapshot::WriteToFile(const std::vector<uint8_t>& snapshotData, const std::wstring& filePath)
{
    std::ofstream file(filePath, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        m_logger->Trace(LOG_ERROR, "Snapshot: failed to open file for writing: %ls",
            filePath.c_str());
        return false;
    }

    file.write((const char*)snapshotData.data(), snapshotData.size());
    if (!file.good()) {
        m_logger->Trace(LOG_ERROR, "Snapshot: write failed");
        return false;
    }

    file.close();
    m_logger->Trace(LOG_INFO, "Snapshot: wrote %zu bytes to %ls", snapshotData.size(), filePath.c_str());
    return true;
}

std::vector<uint8_t> Snapshot::LoadFromFile(const std::wstring& filePath)
{
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        m_logger->Trace(LOG_ERROR, "Snapshot: failed to open file for reading: %ls",
            filePath.c_str());
        return {};
    }

    size_t fileSize = (size_t)file.tellg();
    if (fileSize > kMaxSnapshotSize) {
        m_logger->Trace(LOG_ERROR, "Snapshot: file too large: %zu bytes (max %zu)",
            fileSize, kMaxSnapshotSize);
        return {};
    }

    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> data(fileSize);
    file.read((char*)data.data(), fileSize);

    if (!file.good()) {
        m_logger->Trace(LOG_ERROR, "Snapshot: read failed");
        return {};
    }

    if (!ValidateHeader(data.data(), data.size())) {
        m_logger->Trace(LOG_ERROR, "Snapshot: invalid file header");
        return {};
    }

    m_logger->Trace(LOG_INFO, "Snapshot: loaded %zu bytes from %ls", data.size(), filePath.c_str());
    return data;
}

// ─── Validation ───────────────────────────────────────────────────────

bool Snapshot::ValidateHeader(const uint8_t* data, size_t size)
{
    if (!data || size < sizeof(SnapshotHeader)) return false;

    const SnapshotHeader* header = (const SnapshotHeader*)data;

    if (memcmp(header->magic, "SYMBIOTE", 8) != 0) return false;
    if (header->version != kSnapshotVersion) return false;

    // Basic size sanity check
    if (header->numVcpus > 20) return false; // Sanity cap
    if (header->numMemoryRegions > 1000000) return false; // Sanity cap

    return true;
}

// ─── Describe ─────────────────────────────────────────────────────────

std::string Snapshot::Describe(const std::vector<uint8_t>& snapshotData)
{
    if (!ValidateHeader(snapshotData.data(), snapshotData.size())) {
        return "Invalid snapshot";
    }

    const SnapshotHeader* header = (const SnapshotHeader*)snapshotData.data();

    // Format timestamp
    uint64_t timestampMs = header->timestamp / 10000; // QPC to approx ms
    (void)timestampMs;

    char desc[256];
    snprintf(desc, sizeof(desc),
        "Snapshot: v%u, %u VCPUs, %u memory regions, handler data %u bytes, total %zu bytes",
        header->version,
        header->numVcpus,
        header->numMemoryRegions,
        header->handlerDataSize,
        snapshotData.size());

    return std::string(desc);
}
