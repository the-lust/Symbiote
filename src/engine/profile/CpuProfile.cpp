#include "CpuProfile.h"
#include "ConfigParser.h"
#include <cstring>
#include <algorithm>

static uint64_t MakeLeafKey(uint32_t leaf, uint32_t subleaf) {
    return ((uint64_t)leaf << 32) | subleaf;
}

CpuProfile::CpuProfile()
    : m_tscFrequency(3700000000ULL)
{
}

CpuProfile::~CpuProfile()
{
}

void CpuProfile::LoadFromConfig()
{
    // default: Intel Core i9-10900K
    // leaf 0x0: highest basic leaf + "GenuineIntel" string
    SetLeaf(0x0, 0, 0x00000016, 0x756E6547, 0x6C65746E, 0x49656E69);
    // leaf 0x1: Family 6 Model 165 (A5h) Stepping 5 + features (HyperKD match)
    SetLeaf(0x1, 0, 0x000A0655, 0x00200800, 0x7BFAFBFF, 0xBFEBFBFF);
    // leaf 0x2: cache/TLB descs
    SetLeaf(0x2, 0, 0x76036301, 0x00F0B5FF, 0x00000000, 0x00C30000);
    // leaf 0x4 sub 0: L1 data cache
    SetLeaf(0x4, 0, 0x1C004121, 0x01C0003F, 0x0000003F, 0x00000000);
    // leaf 0x4 sub 1: L1 inst cache
    SetLeaf(0x4, 1, 0x1C004122, 0x01C0003F, 0x0000003F, 0x00000000);
    // leaf 0x4 sub 2: L2 cache
    SetLeaf(0x4, 2, 0x1C004143, 0x01C0003F, 0x000003FF, 0x00000000);
    // leaf 0x4 sub 3: L3 cache (shared)
    SetLeaf(0x4, 3, 0x1C03C163, 0x02C0003F, 0x00000FFF, 0x00000002);
    // leaf 0x7 sub 0: extended features
    SetLeaf(0x7, 0, 0x00000000, 0x029C6FBF, 0x40000000, 0xBC000400);
    // leaf 0x7 sub 1: more features
    SetLeaf(0x7, 1, 0x00000000, 0x00000000, 0x00000000, 0x00000000);

    // topology: i9-10900K = 10C/20T
    // leaf 0xB sub 0: thread level (SMT) — 2 threads/core
    SetLeaf(0xB, 0, 0x00000001, 0x00000002, 0x00000100, 0x00000000);
    // leaf 0xB sub 1: core level — 20 logical processors in package
    SetLeaf(0xB, 1, 0x00000005, 0x00000014, 0x00000201, 0x00000000);
    // leaf 0x1F sub 0: V2 thread level
    SetLeaf(0x1F, 0, 0x00000001, 0x00000002, 0x00000100, 0x00000000);
    // leaf 0x1F sub 1: V2 core level
    SetLeaf(0x1F, 1, 0x00000005, 0x00000014, 0x00000201, 0x00000000);
    // leaf 0x1F sub 2: V2 die/package level
    SetLeaf(0x1F, 2, 0x00000006, 0x00000014, 0x00000302, 0x00000000);

    // extended leaves
    SetLeaf(0x80000000, 0, 0x80000008, 0x00000000, 0x00000000, 0x00000000);
    // leaf 0x80000001: extended features
    SetLeaf(0x80000001, 0, 0x00000000, 0x00000000, 0x00000121, 0x2C100800);
    // leaf 0x80000002-0x80000004: brand string
    // leaf 0x80000005: L1 cache
    SetLeaf(0x80000005, 0, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    // leaf 0x80000006: L2 cache assoc
    SetLeaf(0x80000006, 0, 0x00000000, 0x00000000, 0x02006040, 0x00000000);
    // leaf 0x80000007: power mgmt
    SetLeaf(0x80000007, 0, 0x00000000, 0x00000000, 0x00000000, 0x00000100);
    // Leaf 0x80000008: physical/virtual adress sizes (48/48 bit)
    SetLeaf(0x80000008, 0, 0x0000302C, 0x00000000, 0x00000000, 0x00000000);

    SetBrandString("Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz");
    EncodeBrandToLeaves(0x80000002);
}

void CpuProfile::LoadFromConfig(ConfigParser* config)
{
    if (!config) { LoadFromConfig(); return; }

    // start with Intel defaults
    LoadFromConfig();

    // override leaves from config if present
    struct CfgLeaf {
        uint32_t leaf;
        uint32_t subleaf;
        const char* key;
    };

    CfgLeaf leaves[] = {
        {0x0, 0, "leaf_0x0"}, {0x1, 0, "leaf_0x1"}, {0x2, 0, "leaf_0x2"},
        {0x4, 0, "leaf_0x4_0"}, {0x4, 1, "leaf_0x4_1"}, {0x4, 2, "leaf_0x4_2"}, {0x4, 3, "leaf_0x4_3"},
        {0x7, 0, "leaf_0x7"}, {0x7, 1, "leaf_0x7_1"},
        {0xB, 0, "leaf_0xB_0"}, {0xB, 1, "leaf_0xB_1"},
        {0x1F, 0, "leaf_0x1F_0"}, {0x1F, 1, "leaf_0x1F_1"}, {0x1F, 2, "leaf_0x1F_2"},
        {0x80000000, 0, "leaf_0x80000000"},
        {0x80000001, 0, "leaf_0x80000001"},
        {0x80000002, 0, "leaf_0x80000002"},
        {0x80000003, 0, "leaf_0x80000003"},
        {0x80000004, 0, "leaf_0x80000004"},
        {0x80000005, 0, "leaf_0x80000005"},
        {0x80000006, 0, "leaf_0x80000006"},
        {0x80000007, 0, "leaf_0x80000007"},
        {0x80000008, 0, "leaf_0x80000008"},
    };

    for (auto& cl : leaves) {
        std::string p = cl.key;
        uint32_t eax = (uint32_t)config->GetUint64("cpuid", p + "_eax", 0xFFFFFFFF);
        uint32_t ebx = (uint32_t)config->GetUint64("cpuid", p + "_ebx", 0xFFFFFFFF);
        uint32_t ecx = (uint32_t)config->GetUint64("cpuid", p + "_ecx", 0xFFFFFFFF);
        uint32_t edx = (uint32_t)config->GetUint64("cpuid", p + "_edx", 0xFFFFFFFF);
        if (eax != 0xFFFFFFFF || ebx != 0xFFFFFFFF || ecx != 0xFFFFFFFF || edx != 0xFFFFFFFF) {
            SetLeaf(cl.leaf, cl.subleaf, eax, ebx, ecx, edx);
        }
    }

    // brand string override
    std::string brand = config->GetString("cpuid", "brand_string", "");
    if (!brand.empty()) {
        SetBrandString(brand);
    }

    // TSC freq override
    uint64_t tscFreq = config->GetUint64("cpuid", "tsc_frequency", 0);
    if (tscFreq > 0) {
        m_tscFrequency = tscFreq;
    }
}

void CpuProfile::LoadAmdProfile()
{
    // AMD Ryzen 9 7950X
    // leaf 0x0: highest basic leaf + "AuthenticAMD" string
    SetLeaf(0x0, 0, 0x00000016, 0x68747541, 0x444D4163, 0x69746E65);
    // leaf 0x1: Family 25 Model 48 (Zen 4) Stepping 0
    SetLeaf(0x1, 0, 0x00A10F00, 0x02100800, 0x7FFAFBFF, 0xBFE9FBFF);
    // leaf 0x2: cache descs
    SetLeaf(0x2, 0, 0x76036301, 0x00F0B5FF, 0x00000000, 0x00C30000);
    // leaf 0x4 sub 0-3: cache params (AMD)
    SetLeaf(0x4, 0, 0x1C004121, 0x01C0003F, 0x0000003F, 0x00000000);
    SetLeaf(0x4, 1, 0x1C004122, 0x01C0003F, 0x0000003F, 0x00000000);
    SetLeaf(0x4, 2, 0x1C004143, 0x01C0003F, 0x000003FF, 0x00000000);
    SetLeaf(0x4, 3, 0x1C03C163, 0x02C0003F, 0x00000FFF, 0x00000002);
    // leaf 0x7 sub 0: features
    SetLeaf(0x7, 0, 0x00000000, 0x039C7FBF, 0x40000000, 0xBC000400);
    SetLeaf(0x7, 1, 0x00000000, 0x00000000, 0x00000000, 0x00000000);

    // topology stuff
    SetLeaf(0xB, 0, 0x00000001, 0x00000002, 0x00000100, 0x00000000);
    SetLeaf(0xB, 1, 0x00000004, 0x00000010, 0x00000201, 0x00000000);
    SetLeaf(0x1F, 0, 0x00000001, 0x00000002, 0x00000100, 0x00000001);
    SetLeaf(0x1F, 1, 0x00000004, 0x00000010, 0x00000201, 0x00000001);
    SetLeaf(0x1F, 2, 0x00000008, 0x00000001, 0x00000302, 0x00000001);

    // AMD extended leaves
    SetLeaf(0x80000000, 0, 0x80000023, 0x00000000, 0x00000000, 0x00000000);
    SetLeaf(0x80000001, 0, 0x00A10F00, 0x20000000, 0x000003F3, 0x2B00F800);
    SetLeaf(0x80000005, 0, 0xFF40FF40, 0xFF40FF40, 0x20080140, 0x20080140);
    SetLeaf(0x80000006, 0, 0x00000000, 0x00000000, 0x06008040, 0x00000000);
    SetLeaf(0x80000007, 0, 0x00000000, 0x00000000, 0x00000000, 0x00000500);
    SetLeaf(0x80000008, 0, 0x0000302C, 0x00000000, 0x00000000, 0x00000000);

    // AMD specific leaves
    SetLeaf(0x8000000A, 0, 0x00000001, 0x00000000, 0x00000000, 0x00004000);
    SetLeaf(0x80000019, 0, 0xF040F4B0, 0x00000000, 0x00000000, 0x00000000);
    SetLeaf(0x8000001A, 0, 0x00000003, 0x00000000, 0x00000000, 0x00000000);
    SetLeaf(0x8000001E, 0, 0x00000001, 0x00000001, 0x00000000, 0x00000000);
    SetLeaf(0x8000001F, 0, 0x00000007, 0x00000010, 0x00000000, 0x00000000);

    SetBrandString("AMD Ryzen 9 7950X 16-Core Processor");
    EncodeBrandToLeaves(0x80000002);
}

bool CpuProfile::GetSpoof(uint32_t leaf, uint32_t subleaf, uint32_t* eax, uint32_t* ebx,
                           uint32_t* ecx, uint32_t* edx) const
{
    auto it = m_leaves.find(MakeLeafKey(leaf, subleaf));
    if (it == m_leaves.end()) return false;

    *eax = it->second.eax;
    *ebx = it->second.ebx;
    *ecx = it->second.ecx;
    *edx = it->second.edx;
    return true;
}

void CpuProfile::SetLeaf(uint32_t leaf, uint32_t subleaf, uint32_t eax, uint32_t ebx,
                          uint32_t ecx, uint32_t edx)
{
    m_leaves[MakeLeafKey(leaf, subleaf)] = {eax, ebx, ecx, edx};
}

bool CpuProfile::GetLeaf(uint32_t leaf, uint32_t subleaf, uint32_t* eax, uint32_t* ebx,
                          uint32_t* ecx, uint32_t* edx) const
{
    return GetSpoof(leaf, subleaf, eax, ebx, ecx, edx);
}

void CpuProfile::SetBrandString(const std::string& brand)
{
    m_brandString = brand;
    EncodeBrandToLeaves(0x80000002);
}

void CpuProfile::EncodeBrandToLeaves(uint32_t startLeaf)
{
    const char* brand = m_brandString.empty() ? "Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz" : m_brandString.c_str();
    size_t len = strlen(brand);

    for (uint32_t i = 0; i < 3; i++) {
        uint32_t leaf = startLeaf + i;
        char buf[16] = {0};
        size_t offset = i * 16;
        if (offset < len) {
            memcpy(buf, brand + offset, std::min((size_t)16, len - offset));
        }
        SetLeaf(leaf, 0,
            *(uint32_t*)(buf + 0),
            *(uint32_t*)(buf + 4),
            *(uint32_t*)(buf + 8),
            *(uint32_t*)(buf + 12));
    }
}
