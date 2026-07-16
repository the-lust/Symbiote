# Symbiote — Research Architecture

**Educational / security research only.**

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  Target process — Ring 3                                     │
│  ┌──────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  Proxy DLLs   │→ │ engine.dll  │→ │ MinimalKernel syscall │ │
│  │ ntdll/k32/…  │  │ CodePatcher │  │ VirtualState/Proc…  │ │
│  └──────────────┘  │ KuserHook   │  └─────────────────────┘ │
│                    │ InlineHook  │                            │
│                    └──────┬──────┘                            │
└───────────────────────────┼─────────────────────────────────┘
                            │ WHP API (WHvCreatePartition, …)
┌───────────────────────────▼─────────────────────────────────┐
│  Hyper-V — Type-2 sidecar partition                          │
│  Exit handlers: CPUID, RDTSC, MSR, EPT (KUSER GPA map)       │
└─────────────────────────────────────────────────────────────┘
                            │ fallthrough
┌───────────────────────────▼─────────────────────────────────┐
│  Real Windows kernel + GPU (native D3D/Vulkan via GpuBridge)  │
└─────────────────────────────────────────────────────────────┘
```

### Components

| Layer | Role |
|-------|------|
| **launcher.exe** | Creates suspended target, injects `engine.dll`, calls `Engine_Init`, resumes |
| **engine.dll** | WHP partition, code patches, inline hooks, shared memory |
| **Proxy DLLs** | Forward benign APIs; sensitive paths hit engine / MinimalKernel |
| **MinimalKernel** | Minimal in-process kernel: process, registry, files, syscall handling |
| **WHP sidecar** | Sidecar VM; EPT management |
| **MagicCpuid** | 15-leaf CPUID handshake protocol |
| **TimingCoordinator** | Cross-handler RDTSC detection with jitter strategies |
| **Canary** | Guard-page memory scanner detector |
| **internal verification** | 9-phase fingerprint test suite + handshake_test tool |

## Verification Approach

1. WHP sidecar operational (or graceful degradation)
2. CPUID vendor, signature, hypervisor bit handling
3. RDTSC/RDTSCP timing consistency
4. MSR shadowing
5. KUSER_SHARED_DATA via shared memory
6. PEB offsets
7. NtQuerySystemInformation / NtQueryInformationProcess handling
8. Physical drive, registry, volume serial interception
9. Cross-layer consistency (CPUID ↔ KUSER ↔ syscalls)
10. Magic CPUID handshake protocol verification
11. Brand string consistency
12. JIT memory CPUID interception

## Runtime Requirements

- Windows 10/11 x64
- Hyper-V + Windows Hypervisor Platform enabled (recommended)
- MSVC 2022, CMake 3.20+, Windows SDK with `WinHvPlatform.lib`

## Research Context

For academic study of hardware fingerprinting and hypervisor introspection techniques.
