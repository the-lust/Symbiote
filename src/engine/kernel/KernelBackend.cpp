#include "KernelBackend.h"
#include "SystemProfile.h"

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

bool KernelBackend::HandleRdmsr(uint32_t, uint64_t& value)
{
    value = 0;
    return false;
}

bool KernelBackend::HandleWrmsr(uint32_t, uint64_t)
{
    return false;
}

bool KernelBackend::HandleMemoryRead(uint64_t, void*, size_t)
{
    return false;
}

bool KernelBackend::HandleMemoryWrite(uint64_t, const void*, size_t)
{
    return false;
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
