#include <cstdio>
#include <cassert>
#include "profile/CpuProfile.h"

void test_cpuid_spoofs()
{
    CpuProfile profile;
    profile.LoadFromConfig();

    uint32_t eax, ebx, ecx, edx;

    // Check leaf 0x1 spoof
    assert(profile.GetSpoof(0x1, 0, &eax, &ebx, &ecx, &edx));
    assert(eax == 0x000A0655);
    assert(ebx == 0x02100800);

    // Check brand string
    assert(profile.GetSpoof(0x80000002, 0, &eax, &ebx, &ecx, &edx));
    assert(eax == 0x65746E49); // "Inte"
    assert(ebx == 0x2952286C); // "l(R)"

    // Check TSC frequency default
    assert(profile.GetTscFrequency() == 2800000000ULL);

    printf("  CPUID leaf 0x1 EAX=0x%08X (expected 0x000A0655)\n", eax);
    printf("  Brand string verified\n");
    printf("  TSC frequency: %llu Hz\n", profile.GetTscFrequency());
}
