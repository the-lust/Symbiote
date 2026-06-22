#include <cstdio>
#include <cassert>
#include "profile/CpuProfile.h"
#include "profile/GpuProfile.h"
#include "profile/StorageProfile.h"
#include "profile/TimingProfile.h"

void test_profile_load()
{
    // CpuProfile
    CpuProfile cpu;
    cpu.LoadFromConfig();
    assert(cpu.GetTscFrequency() == 2800000000ULL);
    printf("  CPUProfile: TSC freq = %llu Hz\n", cpu.GetTscFrequency());

    uint32_t eax, ebx, ecx, edx;
    assert(cpu.GetSpoof(0x1, 0, &eax, &ebx, &ecx, &edx));
    printf("  CPUProfile: Leaf 0x1 EAX=0x%08X\n", eax);

    // GpuProfile
    GpuProfile gpu;
    assert(gpu.GetVendorId() == 0x1002);
    assert(gpu.GetDeviceId() == 0x73BF);
    printf("  GPUProfile: Vendor=0x%04X Device=0x%04X\n", gpu.GetVendorId(), gpu.GetDeviceId());

    // StorageProfile
    StorageProfile storage;
    assert(storage.GetTotalSize() == 512ULL * 1024 * 1024 * 1024);
    printf("  StorageProfile: Total=%llu GB\n", storage.GetTotalSize() / (1024*1024*1024));

    // TimingProfile
    TimingProfile timing;
    assert(timing.GetTscFrequency() == 2800000000ULL);
    assert(timing.GetTscOffset() == 0x100000000ULL);
    printf("  TimingProfile: Offset=0x%llX\n", timing.GetTscOffset());
}
