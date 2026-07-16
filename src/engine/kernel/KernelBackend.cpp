#include "KernelBackend.h"
#include "SystemProfile.h"
#include <intrin.h>
#include <excpt.h>
#include <cstring>

KernelBackend::KernelBackend(SystemProfile* profile)
    : m_profile(profile)
{
}

bool KernelBackend::HandleCpuid(uint32_t leaf, uint32_t subleaf, CpuidResult& result)
{
    uint32_t eax, ebx, ecx, edx;
    if (m_profile && m_profile->GetCpuid(leaf, subleaf, eax, ebx, ecx, edx)) {
        result.eax = eax;
        result.ebx = ebx;
        result.ecx = ecx;
        result.edx = edx;
        return true;
    }
    return false;
}

bool KernelBackend::HandleRdtsc(uint64_t& tsc)
{
    tsc = __rdtsc();
    return true;
}

bool KernelBackend::HandleRdtscp(uint64_t& tsc, uint32_t& processorId)
{
    unsigned aux;
    tsc = __rdtscp(&aux);
    processorId = aux;
    return true;
}

bool KernelBackend::HandleRdmsr(uint32_t msr, uint64_t& value)
{
    __try {
        value = __readmsr(msr);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        value = 0;
        return false;
    }
}

bool KernelBackend::HandleWrmsr(uint32_t msr, uint64_t value)
{
    __try {
        __writemsr(msr, value);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool KernelBackend::HandleMemoryRead(uint64_t address, void* buffer, size_t size)
{
    if (!buffer || !address) return false;
    __try {
        memcpy(buffer, (const void*)(uintptr_t)address, size);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool KernelBackend::HandleMemoryWrite(uint64_t address, const void* buffer, size_t size)
{
    if (!buffer || !address) return false;
    __try {
        memcpy((void*)(uintptr_t)address, buffer, size);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

uint64_t KernelBackend::GetTscFrequency() const
{
    return m_profile ? m_profile->GetTscFrequency() : 0;
}

uint64_t KernelBackend::GetTscOffset() const
{
    return m_profile ? m_profile->GetTscOffset() : 0;
}

uint64_t KernelBackend::GetApicFrequency() const
{
    return m_profile ? m_profile->GetApicFrequency() : 0;
}

uint32_t KernelBackend::GetProcessorCount() const
{
    return m_profile ? m_profile->GetProcessorCount() : 1;
}

const char* KernelBackend::GetBrandString() const
{
    return m_profile ? m_profile->GetBrandString() : "";
}

uint16_t KernelBackend::GetNtBuildNumber() const
{
    return m_profile ? m_profile->GetNtBuildNumber() : 0;
}

uint16_t KernelBackend::GetNtMajorVersion() const
{
    return m_profile ? m_profile->GetNtMajorVersion() : 0;
}

uint16_t KernelBackend::GetNtMinorVersion() const
{
    return m_profile ? m_profile->GetNtMinorVersion() : 0;
}
