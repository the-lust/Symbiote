// MSR Reader v5 - Working IOCTL protocol reverse-engineered from semav6msr64 driver
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <cstdio>
#include <cstdlib>

static FILE* g_fp = NULL;

static void logf(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    if (g_fp) vfprintf(g_fp, fmt, args);
    vprintf(fmt, args);
    va_end(args);
}

#pragma pack(push, 1)
struct MsrBuffer {
    DWORD processorBitIndex;  // [0x00] Which CPU to target (0-63)
    DWORD msrIndex;           // [0x04] MSR address
    ULONGLONG msrValue;       // [0x08] MSR value (output for read, input for write)
    DWORD magic1;             // [0x10] Must be 0x58B43AAB
    DWORD magic2;             // [0x14] Must be 0xED624758 (cleared by driver)
};
#pragma pack(pop)

static_assert(sizeof(MsrBuffer) == 0x18, "MsrBuffer must be 24 bytes");

#define IOCTL_READ_MSR  0x222400  // CTL_CODE(0x22, 0x900, BUF, ANY)
#define IOCTL_WRITE_MSR 0x222408  // CTL_CODE(0x22, 0x902, BUF, ANY)
#define IOCTL_CLEAR_MSR 0x222404  // CTL_CODE(0x22, 0x901, BUF, ANY)

struct MsrEntry {
    DWORD msr;
    const char* name;
};

#define MSR_COUNT (sizeof(msrs) / sizeof(msrs[0]))
static MsrEntry msrs[] = {
    // Basic MSRs
    {0x00, "IA32_P5_MC_ADDR"},
    {0x01, "IA32_P5_MC_TYPE"},
    {0x06, "IA32_MONITOR_FILTER_LINE_SIZE"},
    {0x10, "IA32_TSC"},
    {0x17, "IA32_PLATFORM_ID"},
    {0x1B, "IA32_APIC_BASE"},
    {0x20, "IA32_APIC_VERSION"},
    {0x21, "IA32_APIC_TPR"},
    {0x22, "IA32_APIC_APR"},
    {0x23, "IA32_APIC_PPR"},
    {0x24, "IA32_APIC_EOI"},
    {0x25, "IA32_APIC_RRD"},
    {0x26, "IA32_APIC_LDR"},
    {0x27, "IA32_APIC_DFR"},
    {0x28, "IA32_APIC_SVR"},
    {0x2A, "IA32_APIC_ESR"},
    {0x2E, "IA32_APIC_TMR"},
    {0x2F, "IA32_APIC_ICR"},
    {0x30, "IA32_APIC_LVT_TIMER"},
    {0x31, "IA32_APIC_LVT_THERMAL"},
    {0x32, "IA32_APIC_LVT_PERF"},
    {0x33, "IA32_APIC_LVT_LINT0"},
    {0x34, "IA32_APIC_LVT_LINT1"},
    {0x35, "IA32_APIC_LVT_ERROR"},
    {0x36, "IA32_APIC_ICR2"},
    {0x3A, "IA32_FEATURE_CONTROL"},
    {0x3B, "IA32_SMM_MONITOR_CTL"},
    {0x8B, "IA32_BIOS_SIGN_ID"},
    {0x9B, "IA32_SMM_MONITOR"},
    {0xCE, "IA32_PLATFORM_INFO"},
    {0xE2, "IA32_PKG_CAPACITY"},
    {0xE7, "IA32_MPERF"},
    {0xE8, "IA32_APERF"},
    {0xFE, "IA32_MTRR_CAP"},
    {0x174, "IA32_SYSENTER_CS"},
    {0x175, "IA32_SYSENTER_ESP"},
    {0x176, "IA32_SYSENTER_EIP"},
    {0x179, "IA32_MCG_CAP"},
    {0x17A, "IA32_MCG_STATUS"},
    {0x17B, "IA32_MCG_CTL"},
    {0x186, "IA32_PERF_EVT_SEL0"},
    {0x187, "IA32_PERF_EVT_SEL1"},
    {0x188, "IA32_PERF_EVT_SEL2"},
    {0x189, "IA32_PERF_EVT_SEL3"},
    {0x198, "IA32_PERF_STATUS"},
    {0x199, "IA32_PERF_CTL"},
    {0x19A, "IA32_CLOCK_MODULATION"},
    {0x19B, "IA32_THERM_INTERRUPT"},
    {0x19C, "IA32_THERM_STATUS"},
    {0x1A0, "IA32_MISC_ENABLE"},
    {0x1A2, "IA32_TEMPERATURE_TARGET"},
    {0x1A6, "IA32_ENERGY_PERF_BIAS"},
    {0x1B0, "IA32_ENERGY_PERF_BIAS"},
    {0x1B1, "IA32_PKG_THERM_STATUS"},
    {0x1B2, "IA32_PKG_THERM_INTERRUPT"},
    {0x1D9, "IA32_DEBUGCTL"},
    {0x1DB, "IA32_SMM_MONITOR_CTL2"},
    {0x200, "IA32_MTRR_PHYS_BASE0"},
    {0x201, "IA32_MTRR_PHYS_MASK0"},
    {0x202, "IA32_MTRR_PHYS_BASE1"},
    {0x203, "IA32_MTRR_PHYS_MASK1"},
    {0x204, "IA32_MTRR_PHYS_BASE2"},
    {0x205, "IA32_MTRR_PHYS_MASK2"},
    {0x206, "IA32_MTRR_PHYS_BASE3"},
    {0x207, "IA32_MTRR_PHYS_MASK3"},
    {0x208, "IA32_MTRR_PHYS_BASE4"},
    {0x209, "IA32_MTRR_PHYS_MASK4"},
    {0x20A, "IA32_MTRR_PHYS_BASE5"},
    {0x20B, "IA32_MTRR_PHYS_MASK5"},
    {0x20C, "IA32_MTRR_PHYS_BASE6"},
    {0x20D, "IA32_MTRR_PHYS_MASK6"},
    {0x20E, "IA32_MTRR_PHYS_BASE7"},
    {0x20F, "IA32_MTRR_PHYS_MASK7"},
    {0x2FF, "IA32_MTRR_DEF_TYPE"},
    {0x309, "IA32_FIXED_CTR0"},
    {0x38D, "IA32_FIXED_CTR_CTRL"},
    {0x38E, "IA32_PERF_GLOBAL_STAUS"},
    {0x38F, "IA32_PERF_GLOBAL_CTRL"},
    {0x390, "IA32_PERF_GLOBAL_OVF_CTRL"},
    {0x400, "IA32_MC0_CTL"},
    {0x401, "IA32_MC0_STATUS"},
    {0x402, "IA32_MC0_ADDR"},
    {0x403, "IA32_MC0_MISC"},
    {0x404, "IA32_MC1_CTL"},
    {0x405, "IA32_MC1_STATUS"},
    {0x406, "IA32_MC1_ADDR"},
    {0x407, "IA32_MC1_MISC"},
    {0x408, "IA32_MC2_CTL"},
    {0x409, "IA32_MC2_STATUS"},
    {0x40A, "IA32_MC2_ADDR"},
    {0x40B, "IA32_MC2_MISC"},
    {0x40C, "IA32_MC3_CTL"},
    {0x40D, "IA32_MC3_STATUS"},
    {0x40E, "IA32_MC3_ADDR"},
    {0x40F, "IA32_MC3_MISC"},
    {0x410, "IA32_MC4_CTL"},
    {0x411, "IA32_MC4_STATUS"},
    {0x412, "IA32_MC4_ADDR"},
    {0x413, "IA32_MC4_MISC"},
    {0x414, "IA32_MC5_CTL"},
    {0x415, "IA32_MC5_STATUS"},
    {0x416, "IA32_MC5_ADDR"},
    {0x417, "IA32_MC5_MISC"},
    {0x480, "IA32_VMX_BASIC"},
    {0x481, "IA32_VMX_PINBASED_CTLS"},
    {0x482, "IA32_VMX_PROCBASED_CTLS"},
    {0x483, "IA32_VMX_EXIT_CTLS"},
    {0x484, "IA32_VMX_ENTRY_CTLS"},
    {0x485, "IA32_VMX_MISC"},
    {0x486, "IA32_VMX_CR0_FIXED0"},
    {0x487, "IA32_VMX_CR0_FIXED1"},
    {0x488, "IA32_VMX_CR4_FIXED0"},
    {0x489, "IA32_VMX_CR4_FIXED1"},
    {0x48A, "IA32_VMX_VMCS_ENUM"},
    {0x48B, "IA32_VMX_PROCBASED_CTLS2"},
    {0x48C, "IA32_VMX_EPT_VPID_CAP"},
    {0x48D, "IA32_VMX_TRUE_PINBASED_CTLS"},
    {0x48E, "IA32_VMX_TRUE_PROCBASED_CTLS"},
    {0x48F, "IA32_VMX_TRUE_EXIT_CTLS"},
    {0x490, "IA32_VMX_TRUE_ENTRY_CTLS"},
    {0x491, "IA32_VMX_VMFUNC"},
    {0x600, "IA32_DS_AREA"},
    {0x770, "IA32_PM_ENABLE"},
    {0x771, "IA32_HWP_CAPABILITIES"},
    {0x772, "IA32_HWP_REQUEST_PKG"},
    {0x773, "IA32_HWP_INTERRUPT"},
    {0x774, "IA32_HWP_REQUEST"},
    {0x775, "IA32_HWP_STATUS"},
    {0x800, "IA32_X2APIC_TPR"},
    {0x808, "IA32_X2APIC_EOI"},
    {0x80A, "IA32_X2APIC_SVR"},
    {0x831, "IA32_X2APIC_LVT_TIMER"},
    // Extended MSRs
    {0xC0000080, "IA32_EFER"},
    {0xC0000081, "IA32_STAR"},
    {0xC0000082, "IA32_LSTAR"},
    {0xC0000083, "IA32_CSTAR"},
    {0xC0000084, "IA32_FMASK"},
    {0xC0000100, "FS_BASE"},
    {0xC0000101, "GS_BASE"},
    {0xC0000102, "KERNEL_GS_BASE"},
    {0xC0000103, "IA32_TSC_AUX"},
};

static bool ReadMsr(HANDLE hDevice, DWORD msrIndex, DWORD processor, ULONGLONG* value)
{
    MsrBuffer buf;
    buf.processorBitIndex = processor;
    buf.msrIndex = msrIndex;
    buf.msrValue = 0;
    buf.magic1 = 0x58B43AAB;
    buf.magic2 = 0xED624758;

    DWORD ret = 0;
    SetLastError(0);
    BOOL ok = DeviceIoControl(hDevice, IOCTL_READ_MSR,
        &buf, sizeof(buf), &buf, sizeof(buf), &ret, NULL);

    if (ok && ret == sizeof(buf)) {
        *value = buf.msrValue;
        return true;
    }
    return false;
}

int main()
{
    g_fp = fopen("D:/emu/genjutsu/msr_reader_output.txt", "w");

    logf("MSR Reader v5 - Working IOCTL Scanner for semav6msr64\n");
    logf("Protocol reverse-engineered from driver binary\n");
    logf("IOCTL = 0x%08X, Buffer = %zu bytes\n\n", IOCTL_READ_MSR, sizeof(MsrBuffer));

    HANDLE hDevice = CreateFileW(
        L"\\\\.\\semav6msr64",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        logf("ERROR: Failed to open device (error %u)\n", GetLastError());
        if (g_fp) fclose(g_fp);
        printf("Failed. Check output file.\nPress Enter..."); getchar();
        return 1;
    }
    logf("Device opened successfully.\n\n");

    // Test the IOCTL protocol
    ULONGLONG tsc;
    logf("=== Testing IOCTL protocol ===\n\n");

    // Test read TSC with processor 0 (first CPU)
    logf("Trying IOCTL 0x%08X with processor=0, MSR=0x10 (IA32_TSC):\n", IOCTL_READ_MSR);
    if (ReadMsr(hDevice, 0x10, 0, &tsc)) {
        logf("  SUCCESS! TSC = 0x%016llX (%llu)\n",
            (unsigned long long)tsc, (unsigned long long)tsc);
    } else {
        logf("  FAILED with err=%u\n", GetLastError());

        // Try processor affinity = 0xFF (all? or current?)
        if (ReadMsr(hDevice, 0x10, 0xFF, &tsc)) {
            logf("  With processor=0xFF: SUCCESS! TSC = 0x%016llX\n",
                (unsigned long long)tsc);
        } else {
            logf("  With processor=0xFF: FAILED err=%u\n", GetLastError());
        }
    }

    // Now read all known MSRs
    logf("\n=== Reading %zu MSRs on processor 0 ===\n\n", MSR_COUNT);

    int successCount = 0;

    int gpCount = 0;
    ULONGLONG lastTsc = 0;

    for (int i = 0; i < MSR_COUNT; i++) {
        ULONGLONG value = 0;
        bool ok = ReadMsr(hDevice, msrs[i].msr, 0, &value);

        if (ok) {
            logf("0x%05X %-30s 0x%016llX\n",
                msrs[i].msr, msrs[i].name, (unsigned long long)value);
            successCount++;
            if (msrs[i].msr == 0x10) lastTsc = value;
        } else {
            DWORD err = GetLastError();
            if (err == 0) err = 0xE0000100; // likely #GP (not readable)
            logf("0x%05X %-30s #GP (err=%u)\n",
                msrs[i].msr, msrs[i].name, err == 0xE0000100 ? 0 : err);
            gpCount++;
        }

        // If TSC read failed, the protocol itself is wrong, stop
        if (i == 0 && msrs[i].msr == 0x10 && !ok) {
            logf("\nTSC read failed! Protocol may be wrong.\n");
            logf("Let's try different buffer sizes and magic values...\n");

            // Try with the SYSTEM_BUFFER approach - maybe the driver returns status
            // in the output differently
            MsrBuffer testBuf;
            testBuf.processorBitIndex = 0;
            testBuf.msrIndex = 0x10;
            testBuf.msrValue = 0;
            testBuf.magic1 = 0x58B43AAB;
            testBuf.magic2 = 0xED624758;

            DWORD ret = 0;
            SetLastError(0);
            // Try with just 24 bytes out
            BOOL ok2 = DeviceIoControl(hDevice, IOCTL_READ_MSR,
                &testBuf, sizeof(testBuf), &testBuf, sizeof(testBuf), &ret, NULL);
            logf("  retry: ok=%d ret=%u err=%u\n", ok2, ret, GetLastError());
            logf("  buf.msrIndex=%u buf.msrValue=0x%016llX\n",
                testBuf.msrIndex, (unsigned long long)testBuf.msrValue);
            logf("  buf.magic1=0x%08X buf.magic2=0x%08X\n",
                testBuf.magic1, testBuf.magic2);
            break;
        }
    }

    // Read TSC multiple times to see timing change
    logf("\n=== TSC Read Test (10 iterations) ===\n");
    for (int i = 0; i < 10; i++) {
        ULONGLONG val;
        if (ReadMsr(hDevice, 0x10, 0, &val)) {
            logf("TSC[%d] = 0x%016llX\n", i, (unsigned long long)val);
        }
    }

    // Count total
    logf("\n=== Summary ===\n");
    logf("MSRs read: %d, #GP: %d\n", successCount, gpCount);

    // Always show TSC if we got it
    if (successCount > 0) {
        ULONGLONG tscNow;
        if (ReadMsr(hDevice, 0x10, 0, &tscNow)) {
            logf("TSC (IA32_TIME_STAMP_COUNTER): 0x%016llX (%llu)\n",
                (unsigned long long)tscNow, (unsigned long long)tscNow);
        }
    }

    CloseHandle(hDevice);
    logf("\nDone.\n");

    if (g_fp) fclose(g_fp);
    return 0;
}
