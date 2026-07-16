#pragma once
#include <windows.h>
#include <cstdint>

class Logger;

// Patch types for instructions we intercept via INT3
enum class PatchType : uint8_t {
    SGDT = 0,
    SIDT = 1,
    SLDT = 2,
    STR  = 3,
    XGETBV = 4,
    SYSCALL = 5,   // 0F 05 — raw syscall
    RDMSR = 6,     // 0F 32 — read MSR
};

// Patch entry info exposed to VcpuManager for WHP #BP handling
struct PatchEntryInfo {
    PatchType type;
    uint8_t   modrm;
    uint8_t   instrLen;
};

class SystemSpoofer {
public:
    SystemSpoofer(Logger* logger);
    ~SystemSpoofer();

    bool Initialize();

    void SetGdtBase(uint64_t base) { m_gdtBase = base; }
    void SetGdtLimit(uint16_t limit) { m_gdtLimit = limit; }
    void SetIdtBase(uint64_t base) { m_idtBase = base; }
    void SetIdtLimit(uint16_t limit) { m_idtLimit = limit; }
    void SetXgetbvResult(uint64_t value) { m_xgetbvResult = value; }

    // Look up a patched address — used by VcpuManager for WHP #BP exits
    static bool LookupPatch(uint64_t addr, PatchEntryInfo& out);

    // VEH callback for host-side exceptions
    static LONG CALLBACK VectoredHandler(EXCEPTION_POINTERS* ep);

    // EPT-based instruction interception (no INT3 in memory)
    bool HandleEptSyscallIntercept(uint64_t rip, void* context = nullptr);
    bool HandleEptRdmsrIntercept(uint64_t rip, uint32_t msr, uint64_t* value, void* context = nullptr);
    bool HandleEptSysInstrIntercept(uint64_t rip, uint8_t* instruction, uint32_t length, void* context = nullptr);

    // Pointer to synthetic TSC value for consistent timing
    uint64_t* m_syntheticTsc = nullptr;

private:
    static SystemSpoofer* s_instance;

    uint64_t m_gdtBase = 0;
    uint16_t m_gdtLimit = 0;
    uint64_t m_idtBase = 0;
    uint16_t m_idtLimit = 0;
    uint64_t m_xgetbvResult = 0;

    Logger* m_logger = nullptr;
    void* m_vehHandle = nullptr;
    bool m_initialized = false;

    struct Stats {
        int sgdtCount = 0;
        int sidtCount = 0;
        int sldtCount = 0;
        int strCount = 0;
        int xgetbvCount = 0;
        int syscallCount = 0;
        int rdmsrCount = 0;
    } m_stats;

    void ScanAndPatch();
    void ScanRegion(uint8_t* start, SIZE_T size);
    void PatchInstruction(uint64_t addr, PatchType type, uint8_t origByte, uint8_t modrm, int len);
    void ApplyPatches();

    // Hide INT3 patches from integrity verification
    void EnableAntiScan(bool enable);
    bool ApplyCamouflage();
    bool RestorePatches();
    static void GenerateCamouflage(uint8_t* buffer, int len);
};
