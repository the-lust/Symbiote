#pragma once
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <intrin.h>

// Detects host TSC frequency using 3-tier approach from libkrun:
// 1. CPUID 0x15 (TSC/Crystal ratio) — Intel
// 2. CPUID 0x16 (Processor frequency) — Intel
// 3. QPC + RDTSC calibration (10ms busy-wait)
inline uint64_t DetectTscFrequency()
{
    // Tier 1: CPUID 0x15 — TSC/Crystal ratio
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 0);
    uint32_t maxLeaf = (uint32_t)cpuInfo[0];
    if (maxLeaf >= 0x15) {
        __cpuid(cpuInfo, 0x15);
        uint32_t numer = (uint32_t)cpuInfo[1]; // EBX = TSC/Crystal ratio numerator
        uint32_t denom = (uint32_t)cpuInfo[0]; // EAX = denominator
        uint32_t crystal = (uint32_t)cpuInfo[2]; // ECX = crystal frequency Hz
        if (numer != 0 && denom != 0 && crystal != 0) {
            uint64_t freq = (uint64_t)crystal * numer / denom;
            if (freq > 100000000 && freq < 10000000000ULL) return freq;
        }
        if (numer != 0 && denom != 0) {
            if (maxLeaf >= 0x16) {
                __cpuid(cpuInfo, 0x16);
                uint32_t procFreq = (uint32_t)cpuInfo[0]; // EAX = processor frequency MHz
                if (procFreq != 0) {
                    return (uint64_t)procFreq * 1000000;
                }
            }
        }
    }

    // Tier 2: CPUID 0x16 — Processor frequency (MHz)
    if (maxLeaf >= 0x16) {
        __cpuid(cpuInfo, 0x16);
        uint32_t procFreq = (uint32_t)cpuInfo[0];
        if (procFreq != 0) {
            return (uint64_t)procFreq * 1000000;
        }
    }

    // Tier 3: QPC + RDTSC calibration (measure over ~10ms)
    LARGE_INTEGER qpf, qpcStart, qpcNow;
    QueryPerformanceFrequency(&qpf);
    QueryPerformanceCounter(&qpcStart);
    uint64_t tscStart = __rdtsc();
    LONGLONG targetQpc = qpcStart.QuadPart + qpf.QuadPart / 100;
    do {
        QueryPerformanceCounter(&qpcNow);
    } while (qpcNow.QuadPart < targetQpc);
    uint64_t tscEnd = __rdtsc();
    uint64_t tscElapsed = tscEnd - tscStart;
    uint64_t qpcElapsed = (uint64_t)(qpcNow.QuadPart - qpcStart.QuadPart);
    if (qpcElapsed > 0 && qpf.QuadPart > 0) {
        return (tscElapsed * (uint64_t)qpf.QuadPart) / qpcElapsed;
    }

    return 3696000000ULL; // fallback i9-10900K
}

// Detects CPU vendor via CPUID leaf 0x0
// Returns "intel", "amd", or "unknown"
inline const char* DetectCpuVendor()
{
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 0);
    char vendor[13] = {0};
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[3], 4);
    memcpy(vendor + 8, &cpuInfo[2], 4);
    if (memcmp(vendor, "GenuineIntel", 12) == 0) return "intel";
    if (memcmp(vendor, "AuthenticAMD", 12) == 0) return "amd";
    return "unknown";
}

// Auto-generates a generic brand string based on vendor and frequency
inline void GenerateBrandString(const char* vendor, uint64_t tscFreq, char* out, uint32_t outSize)
{
    // Format frequency as X.XX GHz
    char freqStr[16] = {0};
    uint32_t ghz = (uint32_t)(tscFreq / 1000000000);
    uint32_t frac = (uint32_t)((tscFreq % 1000000000) / 10000000); // two decimal places
    snprintf(freqStr, sizeof(freqStr), "%u.%02uGHz", ghz, frac);

    if (strcmp(vendor, "intel") == 0) {
        snprintf(out, outSize, "Intel(R) Core(TM) Processor @ %s", freqStr);
    } else if (strcmp(vendor, "amd") == 0) {
        snprintf(out, outSize, "AMD Ryzen Processor @ %s", freqStr);
    } else {
        snprintf(out, outSize, "x64 Processor @ %s", freqStr);
    }
}

// Applies C3/T2 template feature masks from libkrun for a generic/universal CPU profile.
// Clears features that could leak host CPU model (SGX, AVX-512, MPX, TSX, PMU, etc.)
inline void ApplyFeatureMask(uint32_t leaf, uint32_t subleaf, const char* vendor,
                             uint32_t* eax, uint32_t* ebx, uint32_t* ecx, uint32_t* edx)
{
    (void)subleaf;
    (void)vendor;

    // Leaf 0x1: Feature info — clear hypervisor, SMX, and host-specific bits
    if (leaf == 1) {
        // ECX: clear hypervisor bit, SMX, DTES64, MONITOR, DS_CPL, TM2, CNXT_ID, SDBG, FMA,
        //       XTPR_UPDATE, PDCM, PCID, MOVBE, OSXSAVE
        *ecx &= ~((1u << 31) | (1u << 6) | (1u << 2) | (1u << 3)  | (1u << 4)  |
                  (1u << 7)  | (1u << 10) | (1u << 13) | (1u << 12) | (1u << 14) |
                  (1u << 15) | (1u << 17) | (1u << 22) | (1u << 27));
        // EDX: clear PSN, DS, ACPI, SS, TM, PBE, HTT
        *edx &= ~((1u << 18) | (1u << 21) | (1u << 22) | (1u << 27) |
                  (1u << 28) | (1u << 29) | (1u << 30));
        return;
    }

    // Leaf 0x7 subleaf 0: Structured extended features
    if (leaf == 7 && subleaf == 0) {
        // EBX: clear SGX, BMI1, HLE, AVX2, FPDP, BMI2, INVPCID, RTM, RDT_M, RDT_A,
        //       MPX, AVX512F, AVX512DQ, AVX512IFMA, AVX512PF, AVX512ER, AVX512CD,
        //       AVX512BW, AVX512VL, AVX512VBMI, UMIP, PKU, OSPKE, WAITPKG, AVX512VBMI2,
        //       GFNI, VAES, VPCLULQDQ, AVX512VNNI, AVX512BITALG, AVX512VPOPCNTDQ
        *ebx &= ~((1u << 2)  | (1u << 3)  | (1u << 4)  | (1u << 5)  |
                  (1u << 8)  | (1u << 9)  | (1u << 10) | (1u << 11) |
                  (1u << 12) | (1u << 14) | (1u << 15) | (1u << 16) |
                  (1u << 17) | (1u << 18) | (1u << 19) | (1u << 20) |
                  (1u << 21) | (1u << 22) | (1u << 23) | (1u << 24) |
                  (1u << 26) | (1u << 27) | (1u << 28) | (1u << 29) |
                  (1u << 30) | (1u << 31));
        // ECX: clear AVX512VBMI2, GFNI, VAES, VPCLULQDQ, AVX512VNNI, AVX512BITALG,
        //       AVX512VPOPCNTDQ, RDPID, CLDEMOTE, MOVDIRI, MOVDIR64B, ENQCMD, UMONITOR,
        //       UMWAIT, TPAUSE, CET_SS
        *ecx &= ~((1u << 0)  | (1u << 1)  | (1u << 2)  | (1u << 3)  |
                  (1u << 4)  | (1u << 5)  | (1u << 6)  | (1u << 7)  |
                  (1u << 8)  | (1u << 9)  | (1u << 10) | (1u << 11) |
                  (1u << 12) | (1u << 13) | (1u << 14) | (1u << 15) |
                  (1u << 16));
        // EDX: clear MD_CLEAR, IBRS, STIBP, L1DFL, SSBD
        *edx &= ~((1u << 26) | (1u << 27) | (1u << 28) | (1u << 29) | (1u << 30) | (1u << 31));
        return;
    }

    // Leaf 0x7 subleaf 1: More extended features
    if (leaf == 7 && subleaf == 1) {
        // Clear all extended features (RAX is the main register for subleaf 1)
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        return;
    }

    // Leaf 0xA: PMU version — zero out
    if (leaf == 0xA) {
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        return;
    }

    // Leaf 0xD subleaf 0: XSAVE features — clear MPX and AVX-512 state
    if (leaf == 0xD && subleaf == 0) {
        *ecx &= ~((1u << 3) | (1u << 4) | (1u << 5) | (1u << 6) | (1u << 7)); // MPX + AVX-512
        return;
    }
    if (leaf == 0xD && subleaf == 1) {
        // Clear AVX-512 XSAVE features in EDX
        *edx &= ~((1u << 2) | (1u << 3) | (1u << 4) | (1u << 5) | (1u << 6) | (1u << 7));
        return;
    }

    // Leaf 0x80000001: Extended feature bits
    if (leaf == 0x80000001) {
        // ECX: clear SVM (AMD) or VMX (Intel) as appropriate
        *ecx &= ~((1u << 2) | (1u << 3)  | (1u << 5)  | (1u << 6)  |
                  (1u << 7) | (1u << 8)  | (1u << 9)  | (1u << 10) |
                  (1u << 11));
        // EDX: clear PREFETCH, LZCNT, PDPE1GB
        *edx &= ~((1u << 8) | (1u << 13) | (1u << 26));
        return;
    }

    (void)eax; // eax pass-through for leaves not explicitly masked
}
