#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include <vector>
#include "Logger.h"

class IKernelBackend;
class MagicCpuid;
struct TimingCoordinator;
class CaptureLogger;

class CpuidHandler {
public:
    explicit CpuidHandler(Logger* logger, class IKernelBackend* backend);
    ~CpuidHandler();

    void SetMagicCpuid(MagicCpuid* magic) { m_magicCpuid = magic; }
    void SetTimingCoordinator(TimingCoordinator* tc) { m_timingCoordinator = tc; }
    void SetCaptureLogger(CaptureLogger* cap) { m_captureLogger = cap; }

    bool HandleCpuid(WHV_VP_EXIT_CONTEXT* ctx, uint64_t* rax, uint64_t* rbx,
                     uint64_t* rcx, uint64_t* rdx, uint64_t* rip);

    // Brand string (leaves 0x80000002-0x80000004)
    void SetBrandString(const char* brand);
    const char* GetBrandString() const { return m_brandString; }
    void SetEnhancedBrandString(const char* brand);
    void AutoGenerateBrandString(uint64_t tscFrequency);

    // CPU vendor detection + universal feature masking
    const char* GetCpuVendor() const { return m_cpuVendor; }
    void ApplyUniversalMask(uint32_t leaf, uint32_t subleaf,
                            uint64_t* rax, uint64_t* rbx,
                            uint64_t* rcx, uint64_t* rdx);
    // Populate WHP CPUID result list to reduce VM exits
    void GetComprehensiveCpuidResultList(WHV_X64_CPUID_RESULT* results, int* count, int maxCount);
    void GetCpuidResultList(WHV_X64_CPUID_RESULT* results, int* count, int maxCount);

    // WS-1 policy entry usable from secondary interceptors (e.g. the AllocTracker
    // guard-page VEH) so every CPUID the guest can observe is answered by the
    // same TIP/zero-rule logic. Honors the same per-process passthrough rule as
    // HandleCpuid: pid == registered target (or no target) -> policy; otherwise
    // the real hardware values are returned.
    void EvaluateCpuidForProcess(uint64_t pid, uint32_t leaf, uint32_t subleaf,
                                 uint32_t* eax, uint32_t* ebx,
                                 uint32_t* ecx, uint32_t* edx);

private:
    bool HandleBrandStringLeaf(uint32_t leaf, uint64_t* rax, uint64_t* rbx,
                               uint64_t* rcx, uint64_t* rdx);

    // WS-1 policy: a single evaluate path shared by the VM-exit handler and the
    // WHP CPUID result-list builders, so cached and exit-served leaves answer
    // identically. Order: hypervisor range -> zeros; brand leaves -> brand
    // string; TIP (backend) -> frozen profile values; otherwise ZERO-RULE
    // (unlisted leaves are zeroed, never answered from real hardware).
    // Universal feature mask applied, leaf-1 ECX[31]/SMX cleared.
    void EvaluateLeaf(uint32_t leaf, uint32_t subleaf,
                      uint32_t* eax, uint32_t* ebx, uint32_t* ecx, uint32_t* edx);

    // Throttled log for zero-rule hits (first miss per leaf, then every 1000)
    void LogZeroRuleMiss(uint32_t leaf, uint32_t subleaf);
    uint32_t m_zeroRuleLastLeaf = 0xFFFFFFFF;
    uint32_t m_zeroRuleLastSubleaf = 0xFFFFFFFF;
    uint32_t m_zeroRuleMissCount = 0;
    uint64_t m_zeroRuleTotal = 0;

    // Per-handler exit-latency telemetry (aggregated, logged every 1000 exits)
    uint64_t m_exitCount = 0;
    uint64_t m_exitLatencyAccumCycles = 0;

    // WS-1 result-list builder (shared by GetCpuidResultList /
    // GetComprehensiveCpuidResultList). Covers standard 0x0..0x1F with the
    // profile's subleaves, extended 0x80000000..0x80000008, and the hypervisor
    // range 0x40000000..hvHigh all evaluated through EvaluateLeaf.
    void BuildCpuidResultList(WHV_X64_CPUID_RESULT* results, int* count, int maxCount,
                              uint32_t hvHigh);

    Logger* m_logger;
    class IKernelBackend* m_backend;
    MagicCpuid* m_magicCpuid;
    TimingCoordinator* m_timingCoordinator;
    CaptureLogger* m_captureLogger;

    // Brand string (48 bytes max, split across 3 CPUID leaves)
    char m_brandString[49];
    char m_enhancedBrand[49];
    bool m_hasBrandString;
    bool m_hasEnhancedBrand;
    char m_cpuVendor[16];

public:
    // Serialization for snapshot/restore
    bool Serialize(std::vector<uint8_t>& buffer) const;
    bool Deserialize(const uint8_t* data, size_t size);
};
