#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include "Logger.h"

class IKernelBackend;
class MagicCpuid;
struct TimingCoordinator;

class CpuidHandler {
public:
    explicit CpuidHandler(Logger* logger, class IKernelBackend* backend);
    ~CpuidHandler();

    void SetMagicCpuid(MagicCpuid* magic) { m_magicCpuid = magic; }
    void SetTimingCoordinator(TimingCoordinator* tc) { m_timingCoordinator = tc; }

    bool HandleCpuid(WHV_VP_EXIT_CONTEXT* ctx, uint64_t* rax, uint64_t* rbx,
                     uint64_t* rcx, uint64_t* rdx, uint64_t* rip);

    // Brand string spoofing (leaves 0x80000002-0x80000004)
    void SetBrandString(const char* brand);
    const char* GetBrandString() const { return m_brandString; }
    void SetEnhancedBrandString(const char* brand);

private:
    bool HandleBrandStringLeaf(uint32_t leaf, uint64_t* rax, uint64_t* rbx,
                               uint64_t* rcx, uint64_t* rdx);

    Logger* m_logger;
    class IKernelBackend* m_backend;
    MagicCpuid* m_magicCpuid;
    TimingCoordinator* m_timingCoordinator;

    // Brand string (48 bytes max, split across 3 CPUID leaves)
    char m_brandString[49];
    char m_enhancedBrand[49];
    bool m_hasBrandString;
    bool m_hasEnhancedBrand;
};
