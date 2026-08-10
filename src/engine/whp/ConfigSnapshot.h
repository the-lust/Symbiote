#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <array>

// Maximum proxy DLLs supported
#ifndef SYMBIOTE_KMAXPROXYDLLS
#define SYMBIOTE_KMAXPROXYDLLS
constexpr size_t kMaxProxyDlls = 32;
#endif

struct ProxyRenameEntry {
    wchar_t originalName[64];   // e.g., L"ntdll_proxy.dll"
    wchar_t randomName[64];     // e.g., L"7F3A1B2E.dll"
};

struct CpuProfileSnapshot {
    uint32_t vendor;            // 0=GenuineIntel, 1=AuthenticAMD
    uint32_t family;
    uint32_t model;
    uint32_t stepping;
    uint32_t signature;
    uint32_t maxLeaf;
    uint32_t maxExtLeaf;
    char brandString[64];
    char enhancedBrand[96];
    bool isHybrid;
    uint32_t nativeModelId;     // leaf 0x1A subleaf 0 EAX
    uint32_t coreType;          // leaf 0x1A subleaf 0 EBX
    uint32_t hybridCoreCount;   // leaf 0x1A subleaf 1 EAX
    uint64_t hybridCoreMask;    // leaf 0x1A subleaf 1 EDX:EAX
};

struct TimingProfileSnapshot {
    uint64_t tscFrequencyHz;
    uint32_t tscNoiseAmplitude;
    uint32_t apAperfMperfRatio; // APERF/MPERF ratio * 1000
    bool     enableNoise;
};

struct BiosProfileSnapshot {
    wchar_t biosVendor[64];
    wchar_t biosVersion[64];
    wchar_t biosDate[32];
    wchar_t systemManufacturer[64];
    wchar_t systemProductName[64];
    wchar_t systemSerial[64];
    wchar_t systemUuid[48];
    wchar_t baseboardManufacturer[64];
    wchar_t baseboardProduct[64];
    wchar_t baseboardSerial[64];
    wchar_t chassisSerial[64];
    wchar_t chassisAssetTag[64];
};

struct StorageProfileSnapshot {
    wchar_t diskSerial[32];
    wchar_t diskModel[64];
    wchar_t diskFirmware[16];
    uint8_t ataIdentifyData[512];
};

struct GpuProfileSnapshot {
    uint16_t vendorId;
    uint16_t deviceId;
    uint16_t subSystemId;
    uint32_t driverVersion;
    wchar_t driverPath[260];
    char vulkanIcdPath[260];
};

struct NetworkProfileSnapshot {
    uint8_t macAddress[6];
    wchar_t adapterName[64];
    uint32_t ipv4Address;
    uint32_t dnsServers[4];
};

struct SandboxConfigSnapshot {
    bool enableFileRedirection;
    bool enableRegistryRedirection;
    bool enableIpcFiltering;
    bool enableVirtualDisk;
    wchar_t vhdxPath[MAX_PATH];
    wchar_t mountPoint[MAX_PATH];
    uint64_t vhdxSizeMb;
    wchar_t boxName[64];
};

struct ByovdConfigSnapshot {
    bool enabled;
    wchar_t driverPath[MAX_PATH];    // actual driver used (filled by ByovdDetect)
    uint64_t capabilities;           // bitmask: 1=physMem, 2=kernelR, 4=kernelW, 8=ssdtHook
    HANDLE deviceHandle;             // opened \Device\SymbPhysMem handle
    uint64_t mappedPhysBase;
    size_t mappedPhysSize;
};

struct KernelProxyConfigSnapshot {
    bool enabled;
    bool hookSstd;
    bool hookExGetPreviousMode;
    bool hookEprocess;
    bool hookLstar;
    bool hookIdt;
    bool hookDriverList;
    wchar_t ntoskrnlStubName[64];
    wchar_t dxgkrnlStubName[64];
    wchar_t win32kStubName[64];
};

struct MemoryConfigSnapshot {
    uint32_t sizeMb;
    uint32_t cpuCount;
    bool enableLargePages;
    uint64_t workingSetSize;
};

struct ConfigSnapshot {
    // Version identifier for compatibility
    uint32_t version;
    
    // All profiles baked at launcher setup
    CpuProfileSnapshot cpu;
    TimingProfileSnapshot timing;
    BiosProfileSnapshot bios;
    StorageProfileSnapshot storage;
    GpuProfileSnapshot gpu;
    NetworkProfileSnapshot network;
    SandboxConfigSnapshot sandbox;
    ByovdConfigSnapshot byovd;
    KernelProxyConfigSnapshot kernelProxy;
    MemoryConfigSnapshot memory;

    // Backend type (whp, unicorn) — baked from [backend] section
    wchar_t backendType[32];

    // Target process info — set by Orchestrator Phase 6
    wchar_t targetPath[MAX_PATH];
    wchar_t targetArgs[1024];
    wchar_t targetDirectory[MAX_PATH];
    bool    waitForExit;

    // Proxy DLL rename table
    size_t proxyRenameCount;
    ProxyRenameEntry proxyRenames[kMaxProxyDlls];

    // Random seed for this run
    uint64_t runSeed;

    // Feature flags (which spoofing systems are active)
    bool spoofCpuid;
    bool spoofRdtsc;
    bool spoofMsr;
    bool spoofKuser;
    bool spoofStackSpoofer;
    bool captureMode;
    bool snapshotEnabled;
    bool sandboxEnabled;
};