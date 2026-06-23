#pragma once
#include <cstdint>

struct CpuidResult {
    uint32_t eax = 0;
    uint32_t ebx = 0;
    uint32_t ecx = 0;
    uint32_t edx = 0;
};

class IKernelBackend {
public:
    virtual ~IKernelBackend() = default;

    virtual bool HandleCpuid(uint32_t leaf, uint32_t subleaf, CpuidResult& result) = 0;
    virtual bool HandleRdtsc(uint64_t& tsc) = 0;
    virtual bool HandleRdtscp(uint64_t& tsc, uint32_t& processorId) = 0;
    virtual bool HandleRdmsr(uint32_t msr, uint64_t& value) = 0;
    virtual bool HandleWrmsr(uint32_t msr, uint64_t value) = 0;
    virtual bool HandleMemoryRead(uint64_t address, void* buffer, size_t size) = 0;
    virtual bool HandleMemoryWrite(uint64_t address, const void* buffer, size_t size) = 0;

    // Profile metadata
    virtual uint64_t GetTscFrequency() const = 0;
    virtual uint64_t GetTscOffset() const = 0;
    virtual uint64_t GetApicFrequency() const = 0;
    virtual uint32_t GetProcessorCount() const = 0;
    virtual const char* GetBrandString() const = 0;
    virtual uint16_t GetNtBuildNumber() const = 0;
    virtual uint16_t GetNtMajorVersion() const = 0;
    virtual uint16_t GetNtMinorVersion() const = 0;
};
