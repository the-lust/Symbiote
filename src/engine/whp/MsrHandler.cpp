#include "MsrHandler.h"
#include "capture/CaptureLogger.h"
#include <intrin.h>
#include <string.h>

static bool IsCanonical(uint64_t addr) {
    uint64_t mask = 0xFFFF800000000000ULL;
    return ((addr & mask) == 0) || ((addr & mask) == mask);
}

// Separate function for SEH-safe VMX MSR caching (no C++ object unwinding)
static void CacheVmxMsrs(uint64_t* out, uint32_t count)
{
    __try {
        for (uint32_t i = 0; i < count; i++) {
            out[i] = __readmsr(0x480 + i);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        memset(out, 0, sizeof(out[0]) * count);
    }
}

static void JitterDelay()
{
    LARGE_INTEGER freq, start, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    uint64_t delayUs = (uint64_t)((double)rand() / RAND_MAX * 200.0);
    uint64_t target = (uint64_t)start.QuadPart + (delayUs * (uint64_t)freq.QuadPart) / 1000000;
    do {
        QueryPerformanceCounter(&now);
    } while ((uint64_t)now.QuadPart < target);
}

MsrHandler::MsrHandler(Logger* logger)
    : m_logger(logger), m_captureLogger(nullptr),
      m_efer(1), m_star(0), m_lstar(0), m_cstar(0), m_sfMask(0),
      m_sceAlwaysTrue(true)
{
    srand((unsigned int)GetCurrentProcessId() ^ (unsigned int)(GetTickCount64() ^ 0x80000000));

    // Cache real hardware VMX MSR values (raw helper avoids C++/SEH conflict)
    CacheVmxMsrs(m_vmxMsrs, MSR_IA32_VMX_COUNT);
}

bool MsrHandler::IsValidMsr(uint32_t msr)
{
    // Bare-metal MSR ranges (Hyper-V TLFS MSRs 0x40000000-0x40000FFF intentionally excluded => #GP)
    if (msr <= 0x1FFF) return true;
    if (msr >= 0xC0000000 && msr <= 0xC0001FFF) return true;
    return false;
}

uint64_t MsrHandler::GetSpoofedMsr(uint32_t msr)
{
    // IA32_VMX MSRs (0x480-0x493): return cached real HW values
    if (msr >= MSR_IA32_VMX_RANGE_START && msr <= MSR_IA32_VMX_RANGE_END) {
        return m_vmxMsrs[msr - MSR_IA32_VMX_RANGE_START];
    }

    switch (msr) {
        case MSR_IA32_PLATFORM_ID:        return 0x0ULL;
        case MSR_IA32_BIOS_SIGN_ID:       return 0x0ULL; // No microcode update
        case MSR_IA32_FEATURE_CONTROL:    return 0x4ULL; // Locked, VMX disabled, SMX disabled, SGX disabled
        case MSR_IA32_ARCH_CAPABILITIES:  return 0x0ULL; // No mitigations needed
        case MSR_IA32_MISC_ENABLE:        return 0x400088ULL; // Fast-strings, x87 FPU
        case MSR_IA32_MCG_CAP:            return 0x1EULL;
        case MSR_IA32_MCG_STAT:           return 0x0ULL;
        case MSR_IA32_MTRR_CAP:           return 0x500ULL;
        case MSR_IA32_MTRR_DEF:           return 0x600ULL;
        case MSR_IA32_DEBUGCTL:           return 0x0ULL;
        case MSR_IA32_LASTBRANCHFROM:     return 0x0ULL;
        case MSR_IA32_LASTBRANCHTO:       return 0x0ULL;
        case MSR_IA32_LASTINTFROMIP:      return 0x0ULL;
        case MSR_IA32_LASTINTTOIP:        return 0x0ULL;
        case MSR_IA32_APIC_BASE:          return 0xFEE00800ULL; // Enable, BSP, x2APIC
        case MSR_IA32_SYSENTER_CS:        return 0x10ULL; // Kernel CS selector
        case MSR_IA32_SYSENTER_ESP:       return 0x0ULL;
        case MSR_IA32_SYSENTER_EIP:       return 0x0ULL;
        case MSR_IA32_PERF_STATUS:        return 0x1A00ULL; // 2.6 GHz ratio
        case MSR_IA32_PERF_CTL:           return 0x1A00ULL;
        case MSR_IA32_THERM_STATUS:       return 0x0ULL; // Normal temp
        case MSR_IA32_TEMPERATURE_TARGET: return 0x640064ULL; // 100C target
        case MSR_IA32_PKG_THERM_STATUS:   return 0x0ULL;
        case MSR_IA32_PLATFORM_INFO:      return 0x20000A1C3C00ULL;
        case MSR_IA32_ENERGY_PERF_BIAS:   return 0x6ULL; // Balanced
        case MSR_IA32_PPIN:               return 0x0ULL; // Protected, return 0
        case MSR_IA32_PPIN_CTL:           return 0x0ULL;
        case MSR_IA32_PM_ENABLE:          return 0x0ULL;
        case MSR_IA32_HWP_CAPABILITIES:   return 0x1A2BULL; // Min/Max/Guar/MostEfficient
        case MSR_IA32_HWP_REQUEST_PKG:    return 0x1A00ULL;
        case MSR_IA32_PKG_HDC_CTL:        return 0x0ULL;
        case MSR_IA32_PM_CTL1:            return 0x0ULL;
        case MSR_IA32_THREAD_STALL:       return 0x0ULL;
        case MSR_IA32_DS_AREA:            return 0x0ULL;
        case MSR_IA32_TEST_CTRL:          return 0x0ULL;
        case MSR_IA32_EFER:               return m_efer | (m_sceAlwaysTrue ? 1 : 0);
        case MSR_IA32_STAR:               return m_star;
        case MSR_IA32_LSTAR:              return m_lstar;
        case MSR_IA32_CSTAR:              return m_cstar;
        case MSR_IA32_SFMASK:             return m_sfMask;
        case MSR_IA32_FS_BASE:            return 0x0ULL;
        case MSR_IA32_GS_BASE:            return 0x0ULL;
        case MSR_IA32_KERNEL_GS_BASE:     return 0x0ULL;
        case MSR_HV_GUEST_IDLE:           return 0x0ULL;
        case MSR_IA32_TSC:                return __rdtsc();
        default:                          return 0x0ULL; // All valid-range MSRs return 0
    }
}

bool MsrHandler::HandleMsrRead(WHV_VP_EXIT_CONTEXT*, uint32_t msr, uint64_t* value)
{
    JitterDelay();

    if (!IsValidMsr(msr)) {
        m_logger->Trace(LOG_WARNING, "RDMSR invalid 0x%X => #GP injected", msr);
        return false; // Let WHP inject #GP
    }

    // check tracked MSRs first
    auto it = m_trackedMsrs.find(msr);
    if (it != m_trackedMsrs.end()) {
        *value = it->second;
        if (m_captureLogger) {
            m_captureLogger->CaptureMsr("MSR_READ", 0, msr, *value);
        }
        m_logger->Trace(LOG_WHP, "RDMSR 0x%X (tracked) => 0x%llX", msr, *value);
        return true;
    }

    *value = GetSpoofedMsr(msr);

    if (m_captureLogger) {
        m_captureLogger->CaptureMsr("MSR_READ", 0, msr, *value);
    }

    m_logger->Trace(LOG_WHP, "RDMSR 0x%X => 0x%llX", msr, *value);
    return true;
}

bool MsrHandler::HandleMsrWrite(WHV_VP_EXIT_CONTEXT*, uint32_t msr, uint64_t value)
{
    JitterDelay();

    if (!IsValidMsr(msr)) {
        m_logger->Trace(LOG_WARNING, "WRMSR invalid 0x%X => #GP injected", msr);
        return false;
    }

    // Validate canonical adresses for segment base MSRs
    switch (msr) {
        case MSR_IA32_FS_BASE:
        case MSR_IA32_GS_BASE:
        case MSR_IA32_KERNEL_GS_BASE:
        case MSR_IA32_LSTAR:
        case MSR_IA32_CSTAR:
        case MSR_IA32_SYSENTER_EIP:
        case MSR_IA32_SYSENTER_ESP:
        case MSR_IA32_DS_AREA:
            if (!IsCanonical(value)) {
                m_logger->Trace(LOG_WARNING, "WRMSR 0x%X non-canonical addr 0x%llX => #GP", msr, value);
                return false;
            }
            break;
    }

    switch (msr) {
        case MSR_IA32_EFER:
            m_efer = value | (m_sceAlwaysTrue ? 1 : 0);
            m_logger->Trace(LOG_WHP, "WRMSR EFER => 0x%llX (SCE forced)", m_efer);
            break;

        case MSR_IA32_STAR:
            m_star = value;
            m_trackedMsrs[msr] = value;
            m_logger->Trace(LOG_WHP, "WRMSR STAR => 0x%llX", value);
            break;

        case MSR_IA32_LSTAR:
            m_lstar = value;
            m_trackedMsrs[msr] = value;
            m_logger->Trace(LOG_WHP, "WRMSR LSTAR => 0x%llX", value);
            break;

        case MSR_IA32_CSTAR:
            m_cstar = value;
            m_trackedMsrs[msr] = value;
            m_logger->Trace(LOG_WHP, "WRMSR CSTAR => 0x%llX", value);
            break;

        case MSR_IA32_SFMASK:
            m_sfMask = value;
            m_trackedMsrs[msr] = value;
            m_logger->Trace(LOG_WHP, "WRMSR SFMASK => 0x%llX", value);
            break;

        case MSR_IA32_SYSENTER_CS:
        case MSR_IA32_SYSENTER_ESP:
        case MSR_IA32_SYSENTER_EIP:
        case MSR_IA32_FS_BASE:
        case MSR_IA32_GS_BASE:
        case MSR_IA32_KERNEL_GS_BASE:
        case MSR_IA32_DS_AREA:
            m_trackedMsrs[msr] = value;
            m_logger->Trace(LOG_WHP, "WRMSR 0x%X => 0x%llX", msr, value);
            break;

        case MSR_IA32_PERF_CTL:
            m_logger->Trace(LOG_WHP, "WRMSR PERF_CTL => 0x%llX", value);
            break;

        case MSR_IA32_DEBUGCTL:
            m_logger->Trace(LOG_WHP, "WRMSR DEBUGCTL => 0x%llX", value);
            break;

        case MSR_IA32_MTRR_DEF:
            m_logger->Trace(LOG_WHP, "WRMSR MTRR_DEF => 0x%llX", value);
            break;

        case MSR_IA32_TSC:
            m_logger->Trace(LOG_WHP, "WRMSR TSC => 0x%llX (ignored)", value);
            break;

        case MSR_IA32_APIC_BASE:
            m_logger->Trace(LOG_WHP, "WRMSR APIC_BASE => 0x%llX", value);
            break;

        case MSR_IA32_MISC_ENABLE:
        case MSR_IA32_ENERGY_PERF_BIAS:
        case MSR_IA32_PM_ENABLE:
        case MSR_IA32_HWP_CAPABILITIES:
        case MSR_IA32_HWP_REQUEST_PKG:
        case MSR_IA32_PKG_HDC_CTL:
        case MSR_IA32_PM_CTL1:
        case MSR_IA32_THREAD_STALL:
        case MSR_IA32_PPIN_CTL:
            m_logger->Trace(LOG_WHP, "WRMSR 0x%X => 0x%llX (ignored)", msr, value);
            break;

        case MSR_IA32_BIOS_SIGN_ID:
            m_logger->Trace(LOG_WHP, "WRMSR BIOS_SIGN_ID => 0x%llX", value);
            break;

        case MSR_IA32_FEATURE_CONTROL:
            m_logger->Trace(LOG_WHP, "WRMSR FEATURE_CTRL => 0x%llX (locked)", value);
            break;

        // Hyper-V TLFS MSRs - silently ignore all writes
        case MSR_HV_GUEST_OS_ID:
        case MSR_HV_HYPERCALL:
        case MSR_HV_VP_INDEX:
        case MSR_HV_RESET:
        case MSR_HV_VP_RUNTIME:
        case MSR_HV_TSC_FREQ:
        case MSR_HV_APIC_FREQ:
        case MSR_HV_EOI:
        case MSR_HV_ICR:
        case MSR_HV_TPR:
        case MSR_HV_VP_ASSIST_PAGE:
        case MSR_HV_REENLIGHTENMENT:
        case MSR_HV_TSC_DEADLINE:
        case MSR_HV_REFERENCE_TSC:
        case MSR_HV_GUEST_IDLE:
            break;

        default:
            // IA32_VMX MSRs are read-only on bare metal — inject #GP on write
            if (msr >= MSR_IA32_VMX_RANGE_START && msr <= MSR_IA32_VMX_RANGE_END) {
                m_logger->Trace(LOG_WARNING, "WRMSR VMX 0x%X => #GP (read-only)", msr);
                return false;
            }
            m_logger->Trace(LOG_WHP, "WRMSR 0x%X passthrough => 0x%llX", msr, value);
            return false; // Let WHP handle it
    }

    if (m_captureLogger) {
        m_captureLogger->CaptureMsr("MSR_WRITE", 0, msr, value);
    }

    return true;
}
