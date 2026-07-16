# Symbiote — Configuration Comparison

Real system vs configured profile comparison across fingerprint vectors.
**Real hardware:** Intel Core i7-4510U @ 2.00 GHz (laptop)
**Configured profile:** Intel Core i9-10900K @ 3.70 GHz (desktop)

---

## 1. CPUID

| Leaf | Field | Real (i7-4510U) | Configured (i9-10900K) |
|------|-------|----------------|----------------------|
| 0x0 | Vendor string | `GenuineIntel` | `GenuineIntel` |
| 0x1 | EAX (signature) | `0x00040651` | `0x000A0655` |
| 0x40000000 | VMM leaf | `0x40000005` (Hyper-V) | `0x0` |
| 0x40000001 | Hyper-V features | Non-zero | `0x0` |
| 0x80000002–4 | Brand string | (varies) | `Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz` |

## 2. RDTSC / Timing

| Check | Real | Configured |
|-------|------|-----------|
| TSC frequency | ~2.0 GHz | Configurable |
| RDTSC→CPUID→RDTSC delta | ~80 cycles (bare metal) | VM-exit compensated |
| QPC frequency | 10 MHz (default) | 10 MHz |

## 3. MSR

| MSR | Real | Configured |
|-----|------|-----------|
| IA32_PLATFORM_ID (0x17) | 0x0 | Per-profile |
| IA32_FEATURE_CONTROL (0x3A) | 0x5 | 0x5 |
| IA32_TIME_STAMP_COUNTER (0x10) | Real TSC | Synthetic TSC |

## 4. KUSER_SHARED_DATA

| Field | Real | Configured |
|-------|------|-----------|
| NtMajorVersion (0x260) | 10 | 10 |
| NtMinorVersion (0x261) | 0 | 0 |
| BuildNumber (0x262) | 19045 | 19045 |
| ActiveProcessorCount (0x3C0) | 4 | 4 |

## 5. WMI

| Class | Real | Configured |
|-------|------|-----------|
| Win32_Processor | Real CPU | Profile CPU |
| Win32_ComputerSystem | Real model | Profile model |
| Win32_VideoController | Real GPU | Profile GPU |
| Win32_BaseBoard | Real motherboard | Profile motherboard |
| Win32_BIOS | Real BIOS | Profile BIOS |

## 6. Registry

| Key | Real | Configured |
|-----|------|-----------|
| `HKLM\HARDWARE\DESCRIPTION\System\BIOS` | Real values | Profile values |
| `HKLM\HARDWARE\DESCRIPTION\System\Processor` | Real CPU | Profile CPU |

## 7. Syscall / Process

| Query | Real | Configured |
|-------|------|-----------|
| NtQuerySystemInformation | Real system | Profile values |
| NtQueryInformationProcess | Real process | Debug fields cleared |
| NtQueryVirtualMemory | Real memory | Clean PE headers |
| BeingDebugged | 0/1 | 0 |
| NtGlobalFlag | 0x70/0x0 | 0x0 |

## 8. SMBIOS/DMI

| Table | Real | Configured |
|-------|------|-----------|
| BIOS | Real vendor/version | Profile vendor/version |
| System | Real manufacturer | Profile manufacturer |
| Baseboard | Real model | Profile model |

## 9. Timing

| API | Real | Configured |
|-----|------|-----------|
| QueryPerformanceCounter | Real QPC | Synthetic from TSC base |
| GetTickCount64 | Real | Synthetic |
| GetSystemTime | Real | Synthetic |
| GetSystemTimeAdjustment | Real | Synthetic |

## 10. Network

| Property | Real | Configured |
|----------|------|-----------|
| MAC addresses | Real | Profile values |
| Adapter descriptions | Real | Profile values |

---

## Notes

All values are configurable through `config/config.ini`. The profile system allows per-vector customization through the `[profile]` section. Values were collected from real hardware measurements and reference implementations.
