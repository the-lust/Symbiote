#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include <cstdint>
#include <vector>
#include <string>

class Logger;
class Partition;
class CpuidHandler;
class RdtscHandler;
class MsrHandler;
class EptExecHook;

// Snapshot captures full VCPU + partition + handler state for save/restore.
// Since WHP doesn't provide native snapshot APIs, we manually dump:
//   - VCPU register state for all VCPUs
//   - Memory region tracking (EPT mappings tracked by Partition)
//   - Handler state (CpuidHandler, RdtscHandler, MsrHandler, EptExecHook)
//   - Metadata (timestamp, config version)
//
// The snapshot format:
//   [header: SnapshotHeader]
//   [vcpu state: VcpuStateBlock * numVcpus]
//   [memory regions: MemoryRegionBlock * numMemRegions]
//   [handler state: uint8_t[] serialized handler data]

#pragma pack(push, 1)

struct SnapshotHeader {
    char magic[8];        // "SYMBIOTE\0"
    uint32_t version;     // snapshot format version
    uint32_t numVcpus;
    uint32_t numMemoryRegions;
    uint32_t handlerDataSize;
    uint64_t timestamp;   // QPC timestamp
};

struct MemoryRegionBlock {
    uint64_t gpa;
    uint64_t size;
    uint32_t flags;       // WHV_MAP_GPA_RANGE_FLAGS
    uint8_t  content[1];  // variable-length — actual size = size
};

#pragma pack(pop)

class Snapshot {
public:
    explicit Snapshot(Logger* logger);
    ~Snapshot();

    // Create a snapshot of the current state
    std::vector<uint8_t> Create(Partition* partition,
                                CpuidHandler* cpuidHandler,
                                RdtscHandler* rdtscHandler,
                                MsrHandler* msrHandler,
                                EptExecHook* eptExecHook);

    // Write snapshot to file
    bool WriteToFile(const std::vector<uint8_t>& snapshotData, const std::wstring& filePath);

    // Load snapshot from file
    std::vector<uint8_t> LoadFromFile(const std::wstring& filePath);

    // Restore state from snapshot data
    bool Restore(const std::vector<uint8_t>& snapshotData,
                 Partition* partition,
                 CpuidHandler* cpuidHandler,
                 RdtscHandler* rdtscHandler,
                 MsrHandler* msrHandler,
                 EptExecHook* eptExecHook);

    // Create in-memory snapshot (VCPU regs + handler state only, no memory copy)
    std::vector<uint8_t> CreateInMemory(Partition* partition,
                                        CpuidHandler* cpuidHandler,
                                        RdtscHandler* rdtscHandler,
                                        MsrHandler* msrHandler,
                                        EptExecHook* eptExecHook);

    // Restore from in-memory snapshot
    bool RestoreInMemory(const std::vector<uint8_t>& snapshotData,
                         Partition* partition,
                         CpuidHandler* cpuidHandler,
                         RdtscHandler* rdtscHandler,
                         MsrHandler* msrHandler,
                         EptExecHook* eptExecHook);

    // Validate snapshot header
    static bool ValidateHeader(const uint8_t* data, size_t size);

    // Get human-readable summary of snapshot contents
    std::string Describe(const std::vector<uint8_t>& snapshotData);

private:
    Logger* m_logger;

    static constexpr uint32_t kSnapshotVersion = 1;
    static constexpr size_t kMaxSnapshotSize = 512ULL * 1024 * 1024; // 512 MB

    // Internal helpers
    size_t SaveVcpuRegisters(HANDLE partitionHandle, uint32_t vcpuIndex, uint8_t* buffer, size_t bufferSize);
    bool RestoreVcpuRegisters(HANDLE partitionHandle, uint32_t vcpuIndex, const uint8_t* buffer, size_t dataSize);
};
