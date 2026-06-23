#pragma once
#include "IKernelBackend.h"

class SystemProfile;

class KernelBackend : public IKernelBackend {
public:
    explicit KernelBackend(SystemProfile* profile);

    bool HandleCpuid(uint32_t leaf, uint32_t subleaf, CpuidResult& result) override;
    bool HandleRdtsc(uint64_t& tsc) override;
    bool HandleRdtscp(uint64_t& tsc, uint32_t& processorId) override;
    bool HandleRdmsr(uint32_t msr, uint64_t& value) override;
    bool HandleWrmsr(uint32_t msr, uint64_t value) override;
    bool HandleMemoryRead(uint64_t address, void* buffer, size_t size) override;
    bool HandleMemoryWrite(uint64_t address, const void* buffer, size_t size) override;

    uint64_t GetTscFrequency() const override;
    uint64_t GetTscOffset() const override;
    uint64_t GetApicFrequency() const override;
    uint32_t GetProcessorCount() const override;
    const char* GetBrandString() const override;
    uint16_t GetNtBuildNumber() const override;
    uint16_t GetNtMajorVersion() const override;
    uint16_t GetNtMinorVersion() const override;

private:
    SystemProfile* m_profile;
};
