#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include <unordered_map>
#include "Logger.h"

class CaptureLogger;

class MsrHandler {
public:
    explicit MsrHandler(Logger* logger);

    void SetCaptureLogger(CaptureLogger* cap) { m_captureLogger = cap; }

    bool HandleMsrRead(WHV_VP_EXIT_CONTEXT* ctx, uint32_t msr, uint64_t* value);
    bool HandleMsrWrite(WHV_VP_EXIT_CONTEXT* ctx, uint32_t msr, uint64_t value);

private:
    Logger* m_logger;
    CaptureLogger* m_captureLogger;

    // Standard MSR adresses
    static const uint32_t MSR_IA32_TSC           = 0x10;
    static const uint32_t MSR_IA32_APIC_BASE     = 0x1B;
    static const uint32_t MSR_IA32_BIOS_SIGN_ID  = 0x8B;
    static const uint32_t MSR_IA32_PLATFORM_ID   = 0x17;
    static const uint32_t MSR_IA32_FEATURE_CONTROL = 0x3A;
    static const uint32_t MSR_IA32_ARCH_CAPABILITIES = 0x4A;
    static const uint32_t MSR_IA32_DS_AREA       = 0x600;
    static const uint32_t MSR_IA32_MISC_ENABLE   = 0x1A0;
    static const uint32_t MSR_IA32_ENERGY_PERF_BIAS = 0x1B0;
    static const uint32_t MSR_IA32_MCG_CAP       = 0x179;
    static const uint32_t MSR_IA32_MCG_STAT      = 0x17A;
    static const uint32_t MSR_IA32_DEBUGCTL      = 0x1D9;
    static const uint32_t MSR_IA32_LASTBRANCHFROM = 0x1DB;
    static const uint32_t MSR_IA32_LASTBRANCHTO  = 0x1DC;
    static const uint32_t MSR_IA32_LASTINTFROMIP = 0x1DD;
    static const uint32_t MSR_IA32_LASTINTTOIP   = 0x1DE;
    static const uint32_t MSR_IA32_MTRR_CAP      = 0xFE;
    static const uint32_t MSR_IA32_MTRR_DEF      = 0x2FF;
    static const uint32_t MSR_IA32_SYSENTER_CS   = 0x174;
    static const uint32_t MSR_IA32_SYSENTER_ESP  = 0x175;
    static const uint32_t MSR_IA32_SYSENTER_EIP  = 0x176;
    static const uint32_t MSR_IA32_PERF_STATUS   = 0x198;
    static const uint32_t MSR_IA32_PERF_CTL      = 0x199;
    static const uint32_t MSR_IA32_THERM_STATUS  = 0x19C;
    static const uint32_t MSR_IA32_TEMPERATURE_TARGET = 0x1A2;
    static const uint32_t MSR_IA32_PKG_THERM_STATUS = 0x1B1;
    static const uint32_t MSR_IA32_PLATFORM_INFO = 0xCE;
    static const uint32_t MSR_IA32_PPIN          = 0x17E;
    static const uint32_t MSR_IA32_PPIN_CTL      = 0x17F;
    static const uint32_t MSR_IA32_PM_ENABLE     = 0x770;
    static const uint32_t MSR_IA32_HWP_CAPABILITIES = 0x771;
    static const uint32_t MSR_IA32_HWP_REQUEST_PKG = 0x772;
    static const uint32_t MSR_IA32_PKG_HDC_CTL   = 0x3B0;
    static const uint32_t MSR_IA32_PM_CTL1       = 0x3B1;
    static const uint32_t MSR_IA32_THREAD_STALL  = 0x3B2;
    static const uint32_t MSR_IA32_TEST_CTRL     = 0x33;
    static const uint32_t MSR_IA32_EFER          = 0xC0000080;
    static const uint32_t MSR_IA32_STAR          = 0xC0000081;
    static const uint32_t MSR_IA32_LSTAR         = 0xC0000082;
    static const uint32_t MSR_IA32_CSTAR         = 0xC0000083;
    static const uint32_t MSR_IA32_SFMASK        = 0xC0000084;
    static const uint32_t MSR_IA32_FS_BASE       = 0xC0000100;
    static const uint32_t MSR_IA32_GS_BASE       = 0xC0000101;
    static const uint32_t MSR_IA32_KERNEL_GS_BASE = 0xC0000102;
    // Hyper-V TLFS MSRs (must all return 0/garbage to hide hypervisor)
    static const uint32_t MSR_HV_GUEST_OS_ID     = 0x40000000;
    static const uint32_t MSR_HV_HYPERCALL       = 0x40000001;
    static const uint32_t MSR_HV_VP_INDEX        = 0x40000002;
    static const uint32_t MSR_HV_RESET           = 0x40000003;
    static const uint32_t MSR_HV_VP_RUNTIME      = 0x40000004;
    static const uint32_t MSR_HV_TSC_FREQ        = 0x40000005;
    static const uint32_t MSR_HV_APIC_FREQ       = 0x40000006;
    static const uint32_t MSR_HV_EOI             = 0x40000010;
    static const uint32_t MSR_HV_ICR             = 0x40000020;
    static const uint32_t MSR_HV_TPR             = 0x40000021;
    static const uint32_t MSR_HV_VP_ASSIST_PAGE  = 0x40000022;
    static const uint32_t MSR_HV_REENLIGHTENMENT = 0x40000070;
    static const uint32_t MSR_HV_TSC_DEADLINE    = 0x40000071;
    static const uint32_t MSR_HV_REFERENCE_TSC   = 0x40000072;
    static const uint32_t MSR_HV_GUEST_IDLE      = 0x400000F0;

    // IA32_VMX capability MSRs (0x480-0x493, 20 MSRs)
    static const uint32_t MSR_IA32_VMX_RANGE_START = 0x480;
    static const uint32_t MSR_IA32_VMX_RANGE_END   = 0x493;
    static const uint32_t MSR_IA32_VMX_COUNT       = 20;

    // Tracked MSR state
    uint64_t m_efer;
    uint64_t m_star;
    uint64_t m_lstar;
    uint64_t m_cstar;
    uint64_t m_sfMask;
    bool m_sceAlwaysTrue;

    std::unordered_map<uint32_t, uint64_t> m_trackedMsrs;
    uint64_t m_vmxMsrs[MSR_IA32_VMX_COUNT]; // cached real HW values for 0x480-0x493

    bool IsValidMsr(uint32_t msr);
    uint64_t GetSpoofedMsr(uint32_t msr);
};
