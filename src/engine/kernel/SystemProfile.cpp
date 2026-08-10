#include "SystemProfile.h"
#include "ConfigParser.h"
#include <cstring>
#include <cstdio>

SystemProfile::SystemProfile()
    : m_tscOffset(0ULL), m_apicFrequency(100000000ULL)
{
    LoadIntelI9_10900K();
}

void SystemProfile::LoadFromConfig(ConfigParser* config)
{
    if (!config) return;
    m_tscFrequency = config->GetUint64("timing", "tsc_frequency", m_tscFrequency);
    m_tscOffset = config->GetUint64("timing", "tsc_offset", m_tscOffset);
    m_apicFrequency = config->GetUint64("timing", "apic_frequency", m_apicFrequency);

    uint32_t procCount = (uint32_t)config->GetUint64("system", "processor_count", m_processorCount);
    if (procCount >= 1 && procCount <= 256) m_processorCount = procCount;

    // Frozen-profile rule: if the config carries ANY [cpuid] leaf, it is the
    // authoritative TIP — the built-in default profile is wiped so no leaf can
    // silently leak a default CPU's values (e.g. i9-10900K 3.7GHz leaf 0x16
    // against a 2.0GHz donor). Leaves without a config entry then fall to the
    // zero-rule at the handler.
    bool configHasCpuid = false;
    {
        struct ProbeRange { uint32_t leaf; uint32_t subCount; };
        static const ProbeRange kProbe[] = {
            {0x0,1},{0x1,1},{0x2,1},{0x3,1},{0x4,5},{0x5,1},{0x6,1},{0x7,2},
            {0x8,1},{0x9,1},{0xA,1},{0xB,2},{0xC,1},{0xD,4},{0xE,1},{0xF,1},
            {0x10,1},{0x11,1},{0x12,1},{0x13,1},{0x14,2},{0x15,1},{0x16,1},
            {0x17,1},{0x18,1},{0x19,1},{0x1A,2},{0x1B,1},{0x1C,1},{0x1D,1},
            {0x1E,1},{0x1F,3},
            {0x80000000,1},{0x80000001,1},{0x80000002,1},{0x80000003,1},
            {0x80000004,1},{0x80000005,1},{0x80000006,1},{0x80000007,1},{0x80000008,1},
        };
        for (const auto& r : kProbe) {
            char leafSection[64];
            snprintf(leafSection, sizeof(leafSection), "cpuid.leaf_%X", r.leaf);
            const char* sections[4] = { "cpuid", "cpuid.basic", "cpuid.ext", leafSection };
            for (uint32_t sub = 0; sub < r.subCount && !configHasCpuid; sub++) {
                char keyPlain[64], keySub[64], keyNum[64];
                const char* keys[3] = { nullptr, nullptr, nullptr };
                if (sub == 0) {
                    snprintf(keyPlain, sizeof(keyPlain), "leaf_0x%X", r.leaf);
                    keys[0] = keyPlain;
                }
                snprintf(keySub, sizeof(keySub), "leaf_0x%X_sub%u", r.leaf, sub);
                keys[1] = keySub;
                snprintf(keyNum, sizeof(keyNum), "leaf_0x%X_%u", r.leaf, sub);
                keys[2] = keyNum;
                for (const char* sec : sections) {
                    for (const char* key : keys) {
                        if (!key || !key[0]) continue;
                        if (config->GetUint64(sec, std::string(key) + "_eax", 0xFFFFFFFFu) != 0xFFFFFFFFu) {
                            configHasCpuid = true;
                            break;
                        }
                    }
                    if (configHasCpuid) break;
                }
            }
        }
    }
    if (configHasCpuid) {
        m_cpuidLeaves.clear();
    }

    // WS-1: TIP-driven full-leaf table. Every leaf the frozen profile may carry
    // (standard 0x0..0x1F, extended 0x80000000..0x80000008) is loaded from the
    // [cpuid] section with a convention-agnostic key match, tried in order:
    //   plain  "leaf_0x<LEAF>"            (subleaf 0 only)
    //   "leaf_0x<LEAF>_sub<N>"            (capture/profile convention)
    //   "leaf_0x<LEAF>_<N>"               (older convention)
    // The first variant that yields any non-sentinel value wins. This fixes the
    // previous key-name mismatches (leaf_0x4_0 vs leaf_0x4_sub0) that silently
    // dropped the 0x4/0xB/0xD subleaf entries, and the leaves that were never
    // queried at all (0x5/0x6/0x8/0x9/0xA/0xD), which made the engine serve the
    // built-in i9-10900K default profile instead of the donor's frozen values.
    struct CfgLeafRange { uint32_t leaf; uint32_t subCount; };
    static const CfgLeafRange kRanges[] = {
        {0x0, 1}, {0x1, 1}, {0x2, 1}, {0x3, 1}, {0x4, 5}, {0x5, 1}, {0x6, 1}, {0x7, 2},
        {0x8, 1}, {0x9, 1}, {0xA, 1}, {0xB, 2}, {0xC, 1}, {0xD, 4}, {0xE, 1}, {0xF, 1},
        {0x10, 1}, {0x11, 1}, {0x12, 1}, {0x13, 1}, {0x14, 2}, {0x15, 1}, {0x16, 1},
        {0x17, 1}, {0x18, 1}, {0x19, 1}, {0x1A, 2}, {0x1B, 1}, {0x1C, 1}, {0x1D, 1},
        {0x1E, 1}, {0x1F, 3},
        {0x80000000, 1}, {0x80000001, 1}, {0x80000002, 1}, {0x80000003, 1},
        {0x80000004, 1}, {0x80000005, 1}, {0x80000006, 1}, {0x80000007, 1}, {0x80000008, 1},
    };

    for (const auto& r : kRanges) {
        for (uint32_t sub = 0; sub < r.subCount; sub++) {
            // Key variants, tried per section: plain (subleaf 0), "_subN", "_N"
            char keyPlain[64], keySub[64], keyNum[64];
            const char* keys[3] = { nullptr, nullptr, nullptr };
            if (sub == 0) {
                snprintf(keyPlain, sizeof(keyPlain), "leaf_0x%X", r.leaf);
                keys[0] = keyPlain;
            }
            snprintf(keySub, sizeof(keySub), "leaf_0x%X_sub%u", r.leaf, sub);
            keys[1] = keySub;
            snprintf(keyNum, sizeof(keyNum), "leaf_0x%X_%u", r.leaf, sub);
            keys[2] = keyNum;

            // Sections, most generic first: flat [cpuid] (capture/profile
            // convention), the documented split headers, and per-leaf headers.
            char leafSection[64];
            snprintf(leafSection, sizeof(leafSection), "cpuid.leaf_%X", r.leaf);
            const char* sections[4] = { "cpuid", "cpuid.basic", "cpuid.ext", leafSection };

            bool any = false;
            uint32_t v[4] = {0, 0, 0, 0};
            for (const char* sec : sections) {
                for (const char* key : keys) {
                    if (!key || !key[0]) continue;
                    uint64_t e = config->GetUint64(sec, std::string(key) + "_eax", 0xFFFFFFFFu);
                    uint64_t b = config->GetUint64(sec, std::string(key) + "_ebx", 0xFFFFFFFFu);
                    uint64_t c = config->GetUint64(sec, std::string(key) + "_ecx", 0xFFFFFFFFu);
                    uint64_t d = config->GetUint64(sec, std::string(key) + "_edx", 0xFFFFFFFFu);
                    if (e == 0xFFFFFFFFu && b == 0xFFFFFFFFu && c == 0xFFFFFFFFu && d == 0xFFFFFFFFu)
                        continue;
                    v[0] = (uint32_t)e; v[1] = (uint32_t)b; v[2] = (uint32_t)c; v[3] = (uint32_t)d;
                    any = true;
                    break;
                }
                if (any) break;
            }
            if (any) SetCpuid(r.leaf, sub, v[0], v[1], v[2], v[3]);
        }
    }

    std::string brand = config->GetString("cpuid", "brand_string", "");
    if (!brand.empty()) SetBrandString(brand.c_str());

    LoadHybridFromConfig(config);
}

void SystemProfile::LoadHybridFromConfig(ConfigParser* config)
{
    if (!config) return;
    uint32_t eax = (uint32_t)config->GetUint64("cpuid.0x1A", "native_model_id", 0xFFFFFFFF);
    uint32_t ecx = (uint32_t)config->GetUint64("cpuid.0x1A", "core_type", 0xFFFFFFFF);
    uint32_t sub1eax = (uint32_t)config->GetUint64("cpuid.0x1A", "subleaf1_eax", 0xFFFFFFFF);
    uint32_t sub1ebx = (uint32_t)config->GetUint64("cpuid.0x1A", "subleaf1_ebx", 0xFFFFFFFF);
    uint32_t sub1ecx = (uint32_t)config->GetUint64("cpuid.0x1A", "subleaf1_ecx", 0xFFFFFFFF);
    uint32_t sub1edx = (uint32_t)config->GetUint64("cpuid.0x1A", "subleaf1_edx", 0xFFFFFFFF);

    bool hasAny = (eax != 0xFFFFFFFF || ecx != 0xFFFFFFFF ||
                   sub1eax != 0xFFFFFFFF || sub1ebx != 0xFFFFFFFF ||
                   sub1ecx != 0xFFFFFFFF || sub1edx != 0xFFFFFFFF);
    if (!hasAny) return;

    m_hybridTopology.isHybrid = true;
    m_hybridTopology.nativeModelId = (eax != 0xFFFFFFFFu) ? eax : 0;
    m_hybridTopology.coreType = (ecx != 0xFFFFFFFFu) ? ecx : 0;
    m_hybridTopology.subleaf1Eax = (sub1eax != 0xFFFFFFFFu) ? sub1eax : 0;
    m_hybridTopology.subleaf1Ebx = (sub1ebx != 0xFFFFFFFFu) ? sub1ebx : 0;
    m_hybridTopology.subleaf1Ecx = (sub1ecx != 0xFFFFFFFFu) ? sub1ecx : 0;
    m_hybridTopology.subleaf1Edx = (sub1edx != 0xFFFFFFFFu) ? sub1edx : 0;

    SetCpuid(0x1A, 0, m_hybridTopology.nativeModelId, 0, m_hybridTopology.coreType, 0);
    SetCpuid(0x1A, 1, m_hybridTopology.subleaf1Eax, m_hybridTopology.subleaf1Ebx,
             m_hybridTopology.subleaf1Ecx, m_hybridTopology.subleaf1Edx);
}

bool SystemProfile::GetCpuid(uint32_t leaf, uint32_t subleaf,
    uint32_t& eax, uint32_t& ebx, uint32_t& ecx, uint32_t& edx) const
{
    uint64_t key = ((uint64_t)leaf << 32) | subleaf;
    auto it = m_cpuidLeaves.find(key);
    if (it == m_cpuidLeaves.end()) return false;

    eax = it->second.eax;
    ebx = it->second.ebx;
    ecx = it->second.ecx;
    edx = it->second.edx;
    return true;
}

void SystemProfile::SetCpuid(uint32_t leaf, uint32_t subleaf,
    uint32_t eax, uint32_t ebx, uint32_t ecx, uint32_t edx)
{
    uint64_t key = ((uint64_t)leaf << 32) | subleaf;
    m_cpuidLeaves[key] = { eax, ebx, ecx, edx };
}

void SystemProfile::LoadIntelI9_10900K()
{
    m_tscFrequency = 3696000000ULL;
    m_processorCount = 20;
    m_brandString = "Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz";
    m_gpuVendor = 0x1002;
    m_gpuName = "AMD Radeon RX 6800 XT";
    m_ntMajorVersion = 10;
    m_ntMinorVersion = 0;
    m_ntBuildNumber = 19041;

    // Leaf 0x0: vendor + max leaf
    SetCpuid(0x00, 0x00, 0x00000016, 0x756E6547, 0x6C65746E, 0x49656E69); // GenuineIntel

    // Leaf 0x1: signature + features
    SetCpuid(0x01, 0x00, 0x000A0655, 0x00100800, 0x7BFAFBFB, 0xBFEBFBFF);

    // Leaf 0x2: cache/TLB
    SetCpuid(0x02, 0x00, 0x76036301, 0x00F0B5FF, 0x00000000, 0x00C10000);

    // Leaf 0x4: deterministic cache params
    SetCpuid(0x04, 0x00, 0x1C004121, 0x01C0003F, 0x0000003F, 0x00000000);
    SetCpuid(0x04, 0x01, 0x1C004122, 0x01C0003F, 0x0000003F, 0x00000000);
    SetCpuid(0x04, 0x02, 0x1C004143, 0x01C0003F, 0x000001FF, 0x00000000);
    SetCpuid(0x04, 0x03, 0x1C03C163, 0x02C0003F, 0x00001FFF, 0x00000006);
    SetCpuid(0x04, 0x04, 0x00000000, 0x00000000, 0x00000000, 0x00000000);

    // Leaf 0x5: MONITOR/MWAIT
    SetCpuid(0x05, 0x00, 0x00000040, 0x00000040, 0x00000003, 0x00000020);

    // Leaf 0x6: thermal/power
    SetCpuid(0x06, 0x00, 0x000027F7, 0x00000002, 0x00000009, 0x00000000);

    // Leaf 0x7: extended features
    SetCpuid(0x07, 0x00, 0x00000000, 0x000027AB, 0x00000000, 0xBC000400);
    SetCpuid(0x07, 0x01, 0x00000000, 0x00000000, 0x00000000, 0x00000000);

    // Leaf 0x8: linear address sizes
    SetCpuid(0x08, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);

    // Leaf 0x9: DCA
    SetCpuid(0x09, 0x00, 0x00000001, 0x00000000, 0x00000000, 0x00000000);

    // Leaf 0xA: PMU
    SetCpuid(0x0A, 0x00, 0x07300803, 0x00000000, 0x00000000, 0x00000000);

    // Leaf 0xB: extended topology
    SetCpuid(0x0B, 0x00, 0x00000001, 0x00000002, 0x00000100, 0x00000000);
    SetCpuid(0x0B, 0x01, 0x00000005, 0x00000014, 0x00000201, 0x00000000);

    // Leaf 0xD: XSAVE
    SetCpuid(0x0D, 0x00, 0x00000007, 0x00000340, 0x00000340, 0x00000000);
    SetCpuid(0x0D, 0x01, 0x00000001, 0x00000000, 0x00000000, 0x00000000);

    // Leaf 0x10: QoS
    SetCpuid(0x10, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);

    // Leaf 0x12: SGX
    SetCpuid(0x12, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);

    // Leaf 0x14: Intel PT
    SetCpuid(0x14, 0x00, 0x00000001, 0x0000004F, 0x00000000, 0x00000000);
    SetCpuid(0x14, 0x01, 0x0000004F, 0x00000000, 0x00000000, 0x00000000);

    // Leaf 0x15: TSC frequency
    SetCpuid(0x15, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);

    // Leaf 0x16: processor frequency
    SetCpuid(0x16, 0x00, 0x00000E74, 0x00000E74, 0x00000064, 0x00000000);

    // Leaf 0x19: SGX resource enum — masked (SGX disabled in leaf 0x12)
    SetCpuid(0x19, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);

    // Leaf 0x1A: hybrid topology — not supported on i9-10900K (Comet Lake, all P-cores)
    SetCpuid(0x1A, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x1A, 0x01, 0x00000000, 0x00000000, 0x00000000, 0x00000000);

    // Leaf 0x1F: VMD topology — all zeros (not supported on i9-10900K)
    // Real max leaf is 0x16, so 0x1F should return zeros
    SetCpuid(0x1A, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x1A, 0x01, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x1F, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);

    // Hypervisor leafs - hidden
    SetCpuid(0x40000000, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x40000001, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);

    // Extended leafs
    SetCpuid(0x80000000, 0x00, 0x80000008, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x80000001, 0x00, 0x00000000, 0x00000000, 0x00000121, 0x2C100000);
    SetCpuid(0x80000002, 0x00, 0x65746E49, 0x2952286C, 0x726F4320, 0x4D542865);
    SetCpuid(0x80000003, 0x00, 0x35692029, 0x3030392D, 0x4B203030, 0x75282043);
    SetCpuid(0x80000004, 0x00, 0x37332E33, 0x48473030, 0x0000007A, 0x00000000);
    SetCpuid(0x80000006, 0x00, 0x00000000, 0x00000000, 0x01006040, 0x00000000);
    SetCpuid(0x80000007, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000100);
    SetCpuid(0x80000008, 0x00, 0x00003027, 0x00000000, 0x00000000, 0x00000000);
}

void SystemProfile::LoadIntelI9_13900K()
{
    m_tscFrequency = 5800000000ULL;
    m_processorCount = 32;
    m_brandString = "Intel(R) Core(TM) i9-13900K";
    m_gpuVendor = 0x10DE;
    m_gpuName = "NVIDIA GeForce RTX 4090";
    m_ntMajorVersion = 10;
    m_ntMinorVersion = 0;
    m_ntBuildNumber = 22621;
    m_hybridTopology.isHybrid = true;
    m_hybridTopology.nativeModelId = 0x00000000;
    m_hybridTopology.coreType = 0; // default for subleaf 0

    SetCpuid(0x00, 0x00, 0x00000020, 0x756E6547, 0x6C65746E, 0x49656E69);
    SetCpuid(0x01, 0x00, 0x000B06F2, 0x00100800, 0x7FFAFBFF, 0xBFEBFBFF);
    SetCpuid(0x02, 0x00, 0x76036301, 0x00F0B5FF, 0x00000000, 0x00C30000);
    SetCpuid(0x04, 0x00, 0x1C004121, 0x01C0003F, 0x0000003F, 0x00000000);
    SetCpuid(0x04, 0x01, 0x1C004122, 0x01C0003F, 0x0000003F, 0x00000000);
    SetCpuid(0x04, 0x02, 0x1C004143, 0x01C0003F, 0x000001FF, 0x00000000);
    SetCpuid(0x04, 0x03, 0x1C03C163, 0x02C0003F, 0x00001FFF, 0x00000006);
    SetCpuid(0x04, 0x04, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x05, 0x00, 0x00000040, 0x00000040, 0x00000003, 0x00000020);
    SetCpuid(0x06, 0x00, 0x000027F7, 0x00000002, 0x00000009, 0x00000000);
    SetCpuid(0x07, 0x00, 0x00000001, 0x029C6FBF, 0x40000000, 0xBC000400);
    SetCpuid(0x07, 0x01, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x08, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x09, 0x00, 0x00000001, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x0A, 0x00, 0x07300803, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x0B, 0x00, 0x00000001, 0x00000002, 0x00000100, 0x00000003);
    SetCpuid(0x0B, 0x01, 0x00000005, 0x00000020, 0x00000201, 0x00000003);
    SetCpuid(0x0D, 0x00, 0x00000007, 0x00000340, 0x00000340, 0x00000000);
    SetCpuid(0x0D, 0x01, 0x00000001, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x0E, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x0F, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x10, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x11, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x12, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x13, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x14, 0x00, 0x00000001, 0x0000004F, 0x00000000, 0x00000000);
    SetCpuid(0x14, 0x01, 0x0000004F, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x15, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x16, 0x00, 0x000016A0, 0x000016A0, 0x00000064, 0x00000000);
    SetCpuid(0x17, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x18, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x19, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x1A, 0x00, 0x00000001, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x1A, 0x01, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x1F, 0x00, 0x00000001, 0x00000004, 0x00000100, 0x00000003);
    SetCpuid(0x1F, 0x01, 0x00000006, 0x00000020, 0x00000201, 0x00000003);
    SetCpuid(0x1F, 0x02, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x40000000, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x40000001, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x80000000, 0x00, 0x80000008, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x80000001, 0x00, 0x00000000, 0x00000000, 0x00000121, 0x2C100000);
    SetCpuid(0x80000002, 0x00, 0x65746E49, 0x2952286C, 0x726F4320, 0x4D542865);
    SetCpuid(0x80000003, 0x00, 0x35692029, 0x392D392D, 0x30333030, 0x204B204B);
    SetCpuid(0x80000004, 0x00, 0x30303030, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x80000006, 0x00, 0x00000000, 0x00000000, 0x01006040, 0x00000000);
    SetCpuid(0x80000007, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000100);
    SetCpuid(0x80000008, 0x00, 0x0000302E, 0x00000000, 0x00000000, 0x00000000);
}

void SystemProfile::EncodeBrandToLeaves(uint32_t startLeaf)
{
    const char* brand = m_brandString.empty() ? "Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz" : m_brandString.c_str();
    size_t len = strlen(brand);

    for (uint32_t i = 0; i < 3; i++) {
        char buf[16] = {0};
        size_t offset = i * 16;
        if (offset < len) {
            size_t copyLen = (len - offset > 16) ? 16 : (len - offset);
            memcpy(buf, brand + offset, copyLen);
        }
        SetCpuid(startLeaf + i, 0,
            *(uint32_t*)(buf + 0),
            *(uint32_t*)(buf + 4),
            *(uint32_t*)(buf + 8),
            *(uint32_t*)(buf + 12));
    }
}

void SystemProfile::LoadAmdRyzen9_5950X()
{
    m_tscFrequency = 3400000000ULL;
    m_processorCount = 32;
    m_brandString = "AMD Ryzen 9 5950X 16-Core Processor";
    m_gpuVendor = 0x10DE;
    m_gpuName = "NVIDIA GeForce RTX 3090";
    m_ntMajorVersion = 10;
    m_ntMinorVersion = 0;
    m_ntBuildNumber = 19041;

    SetCpuid(0x00, 0x00, 0x00000010, 0x68747541, 0x444D4163, 0x69746E65); // AuthenticAMD

    SetCpuid(0x01, 0x00, 0x00A20F12, 0x00300800, 0x7ED8320B, 0x178BFBFF);

    SetCpuid(0x02, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);

    SetCpuid(0x05, 0x00, 0x00000040, 0x00000040, 0x00000003, 0x00000000);

    SetCpuid(0x06, 0x00, 0x02100FEF, 0x00000002, 0x00000000, 0x00000000);

    SetCpuid(0x07, 0x00, 0x00000000, 0x209C01A9, 0x00000000, 0x00000000);

    SetCpuid(0x08, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);

    SetCpuid(0x0A, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);

    SetCpuid(0x0B, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);

    SetCpuid(0x0D, 0x00, 0x00000007, 0x00000340, 0x00000340, 0x00000000);
    SetCpuid(0x0D, 0x01, 0x00000001, 0x00000000, 0x00000000, 0x00000000);

    SetCpuid(0x0E, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);

    SetCpuid(0x0F, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);

    SetCpuid(0x10, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);

    // Hypervisor leafs - hidden
    SetCpuid(0x40000000, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x40000001, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);

    // Extended leafs
    SetCpuid(0x80000000, 0x00, 0x8000001F, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x80000001, 0x00, 0x00A20F12, 0x20000000, 0x75C237FF, 0x2FD3FBFF);
    SetCpuid(0x80000002, 0x00, 0x20444D41, 0x657A7952, 0x2039206E, 0x30353935);
    SetCpuid(0x80000003, 0x00, 0x33312058, 0x72632D36, 0x6F72506F, 0x73736563);
    SetCpuid(0x80000004, 0x00, 0x0000726F, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x80000005, 0x00, 0xFF40FF40, 0xFF40FF40, 0x20080140, 0x40040140);
    SetCpuid(0x80000006, 0x00, 0x64006400, 0x64006400, 0x02006140, 0x0080C140);
    SetCpuid(0x80000007, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000100);
    SetCpuid(0x80000008, 0x00, 0x00003030, 0x00000000, 0x00001003, 0x00000000);
    SetCpuid(0x8000000A, 0x00, 0x00000001, 0x00008000, 0x00000000, 0x00021B6F);
    SetCpuid(0x80000019, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x8000001A, 0x00, 0x00000003, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x8000001B, 0x00, 0x000000FF, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x8000001C, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x8000001D, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x8000001E, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    SetCpuid(0x8000001F, 0x00, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
}
