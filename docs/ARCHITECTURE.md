# Symbiote — Research Architecture

**Educational / security research only.** This document describes how the WHP-based Ring-3 research platform models hardware fingerprinting and spoofing.

## Problem Statement

Executable-binaries protection systems bind license tokens to composite hardware fingerprints (CPUID, KUSER_SHARED_DATA, MSRs, timing, syscalls, disk/registry, PEB). Traditional interception approaches load **unsigned kernel drivers** and intercept at VMX/SVM layer.

This project uses Microsofts Hyper-V (Ring -1) via the **Windows Hypervisor Platform (WHP) API** from **Ring 3**, with no custom kernel driver required.

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
| **Proxy DLLs** | Forward benign APIs; sensitive paths hit engine / MinimalKernel |
| **MinimalKernel** | Minimal in-process kernel: spoofed handles, registry, files, syscalls |
| **WHP sidecar** | Sidecar VM + multi-VCPU; EPT maps spoofed KUSER page |
| **CodePatcher** | UD2 + VEH on CPUID/RDTSC/RDTSCP in target `.text` |
| **MagicCpuid** | 15-leaf handshake protocol: PID registration, syscall handler exchange, enhanced mode, shared memory GPA, quit |
| **TimingCoordinator** | Cross-handler RDTSC→CPUID→RDTSC pattern detection with 3 jitter strategies |
| **Canary** | Guard-page memory scanner detector with VEH callback; 4KB handshake page |
| **internal verification** | 9-phase fingerprint test suite + handshake_test tool |

## vs Ring -1/-2 Custom Hypervisors

| Aspect | Custom Ring -1/-2 Hypervisor | Symbiote (WHP path) |
|--------|-------------------------------|-------------------|
| Kernel driver | Required (unsigned) | None |
| DSE / PatchGuard interception | Often required | Not required |
| BSOD risk from HV bugs | High (Ring 0/-1) | Lower (user-mode + Hyper-V) |
| GPU | Native | Native (GpuBridge fallthrough) |
| Auditability | Obfuscated scene binaries | Full source in Ring 3 |
| Hyper-V dependency | Disable/compete with VBS | Uses Hyper-V / WHP |

The KUSER and CPUID profile values (i9-10900K, Z490, RX 6800 XT) were calibrated against real hardware measurements and existing reference implementations.

## Verification Approach

Symbiote is verified by running target executables under `launcher.exe` and observing engine log output + tool output:

1. WHP sidecar operational (or graceful degradation)  
2. CPUID vendor, signature, hypervisor bit hidden  
3. RDTSC/RDTSCP timing consistency around CPUID  
4. MSR shadowing (via MsrPatcher when engine active)  
5. KUSER_SHARED_DATA spoofed via EPT / VEH  
6. PEB offsets cleaned  
7. NtQuerySystemInformation / NtQueryInformationProcess handled by MinimalKernel  
8. Physical drive, registry, volume serial blocked/spoofed  
9. Cross-layer consistency (CPUID ↔ KUSER ↔ syscalls)  
10. Magic CPUID handshake leaves verified via handshake_test tool  
11. Brand string leaves 0x80000002-4 config-driven and consistent with registry spoofing  
12. AllocTracker full register emulation (no UD2) for JIT memory CPUID

See [`docs/RESULTS.md`](RESULTS.md) for detailed verification data.

## Runtime Requirements

- Windows 10/11 x64  
- **Recommended:** Hyper-V + Windows Hypervisor Platform enabled  
  - Optional Features → Hyper-V, Virtual Machine Platform, Windows Hypervisor Platform  
- Admin not strictly required (injection uses standard APIs)  
- MSVC 2022, CMake 3.20+, Windows SDK with `WinHvPlatform.lib`

If WHP is unavailable, engine degrades to **IAT + inline hook + VEH** mode (launcher logs "degraded mode").

## Detection Surface (Defensive Research)

CPUID 0x40000000, EPT hook timing, hypervisor leaves, driver enumeration, DSE flags, LSTAR syscall handler scanning, RDTSC→CPUID→RDTSC timing deltas, memory pattern scanning for guard pages. This platform reduces driver footprint but still presents WHP/Hyper-V and VEH patch artifacts. TimingCoordinator provides jitter injection and delta normalization to mask VM exit side-channels; Canary detects when memory is being scanned for hooked pages.

## Research Context

For academic study of hardware fingerprinting and hypervisor introspection techniques.  
