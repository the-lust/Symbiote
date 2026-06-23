# Symbiote — Research Architecture

**Educational / security research only.** This document describes how the WHP-based Ring-3 research platform models hardware fingerprinting and spoofing, as an alternative to custom ring -1/-2 hypervisors (SimpleSVM, HyperDBG, and others).

## Problem Statement

Executable-binaries protection systems bind license tokens to composite hardware fingerprints (CPUID, KUSER_SHARED_DATA, MSRs, timing, syscalls, disk/registry, PEB). Traditional bypass approaches load **unsigned kernel drivers** and intercept at VMX/SVM layer.

This project uses Microsofts Hyper-V (Ring -1) via the **Windows Hypervisor Platform (WHP) API** from **Ring 3**, with no custom kernel driver required.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  Target process (game / PoC) — Ring 3                       │
│  ┌──────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ Proxy DLLs   │→ │ engine.dll  │→ │ SoGen syscall emu   │ │
│  │ ntdll/k32/…  │  │ CodePatcher │  │ VirtualState/Proc…  │ │
│  └──────────────┘  │ KuserHook   │  └─────────────────────┘ │
│                    │ InlineHook  │                            │
│                    └──────┬──────┘                            │
└───────────────────────────┼─────────────────────────────────┘
                            │ WHP API (WHvCreatePartition, …)
┌───────────────────────────▼─────────────────────────────────┐
│  Hyper-V (Microsoft, Ring -1) — Type-2 sidecar partition    │
│  Exit handlers: CPUID, RDTSC, MSR, EPT (KUSER GPA map)        │
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
| **engine.dll** | WHP partition, VEH code patches, ntdll inline hooks, KUSER shared memory |
| **Proxy DLLs** | Forward benign APIs; sensitive paths hit engine / SoGen |
| **SoGen emulator** | Minimal in-process kernel: spoofed handles, registry, files, syscalls |
| **WHP sidecar** | Sidecar VM + multi-VCPU; EPT maps spoofed KUSER page |
| **CodePatcher** | UD2 + VEH on CPUID/RDTSC/RDTSCP in target `.text` |
| **internal verification** | 9-phase fingerprint test suite (internal dev only) |

## vs Ring -1/-2 Custom Hypervisors

| Aspect | SimpleSVM / HyperDBG / HyperKD | Symbiote (WHP path) |
|--------|--------------------------------|-------------------|
| Kernel driver | Required (unsigned) | None |
| DSE / PatchGuard bypass | Often required | Not required |
| BSOD risk from HV bugs | High (Ring 0/-1) | Lower (user-mode + Hyper-V) |
| GPU | Native | Native (GpuBridge fallthrough) |
| Auditability | Obfuscated scene binaries | Full source in Ring 3 |
| Hyper-V dependency | Disable/compete with VBS | Uses Hyper-V / WHP |

Reference implementation patterns were reviewed in `Desktop/emu/hatsune-miku-hv-src` (HyperKD / SimpleSVM) for **fingerprint field values** (i9-10900K profile, KUSER structure), not for driver loading.

## Verification Approach

Symbiote is verified by running target executables under `launcher.exe` and observing engine log output + tool output:

1. WHP sidecar operational (or graceful degradation)  
2. CPUID vendor, signature, hypervisor bit hidden  
3. RDTSC/RDTSCP timing consistency around CPUID  
4. MSR shadowing (via MsrPatcher when engine active)  
5. KUSER_SHARED_DATA spoofed via EPT / VEH  
6. PEB offsets cleaned  
7. NtQuerySystemInformation / NtQueryInformationProcess handled by SoGen  
8. Physical drive, registry, volume serial blocked/spoofed  
9. Cross-layer consistency (CPUID ↔ KUSER ↔ syscalls)

See [`docs/RESULTS.md`](RESULTS.md) for detailed verification data.

## Runtime Requirements

- Windows 10/11 x64  
- **Recommended:** Hyper-V + Windows Hypervisor Platform enabled  
  - Optional Features → Hyper-V, Virtual Machine Platform, Windows Hypervisor Platform  
- Admin not strictly required for PoC (injection uses standard APIs)  
- MSVC 2022, CMake 3.20+, Windows SDK with `WinHvPlatform.lib`

If WHP is unavailable, engine degrades to **IAT + inline hook + VEH** mode (launcher logs "degraded mode").

## Detection Surface (Defensive Research)

CPUID 0x40000000, EPT hook timing, hypervisor leaves, driver enumeration, DSE flags. This platform reduces driver footprint but still presents WHP/Hyper-V and VEH patch artifacts.

## Ethics

For academic study of hardware fingerprinting and hypervisor introspection. Not for circumventing copy protection on commercial titles you do not own.

## References

- [momo5502/sogen](https://github.com/momo5502/sogen) — syscall emulator inspiration  
- Microsoft WHP API documentation — Windows Hypervisor Platform  
- CrackL@b RE:Requiem analysis (Rose/Natasha) — hypervisor bypass taxonomy  
