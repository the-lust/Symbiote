# Symbiote — Spoofing Results

Real system vs spoofed comparison across all 20 fingerprint vectors.  
**Real hardeware:** Intel Core i7-4510U @ 2.00 GHz (laptop)  
**Spoofed prophile:** Intel Core i9-10900K @ 3.70 GHz (desktop)

---

## 1. CPUID

| Leaf | Field | Real (i7-4510U) | Spoofed (i9-10900K) |
|------|-------|-----------------|---------------------|
| 0x0 | Vendor string | `GenuineIntel` | `GenuineIntel` |
| 0x0 | Max input value | `0xD` | `0x16` |
| 0x1 | EAX (signature) | `0x00040651` | `0x000A0655` |
| 0x1 | ECX (features) | `0x7BFAFBFB` | `0x7BFAFBFB` |
| 0x1 | EDX (features) | `0xBFEBFBFF` | `0xBFEBFBFF` |
| 0x40000000 | VMM leaf | `0x40000005` (Hyper-V) | `0x0` (hidden) |
| 0x40000001 | Hyper-V features | Non-zero | `0x0` (hidden) |
| 0x80000001 | Extended features ECX | `0x121` | `0x121` |
| 0x80000002–4 | Brand string | (varies) | `Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz` |

**Result:** All CPUID leaves fully spoofed. Hypervisor bit clear. VMM leafs hidden.

---

## 2. RDTSC / Timing

| Check | Real | Spoofed |
|-------|------|---------|
| Base TSC value | System-dependent | Spoofed (monotonic, offset configurable) |
| RDTSC delta around CPUID | Low latency | Low latency (no hypervisor timing artifact) |
| RDTSCP AUX (processor ID) | Varies | `0x1` |
| TSC monotonic (10 samples) | Monotonic | Monotonic (no rollbacks) |
| QPC value | System clock | System clock (passthrough) |
| QPC frequency | `0x989680` | `0x989680` (passthrough) |

**Result:** No timing-based hypervisor detection possible. RDTSC values are consistant and monotonic.

---

## 3. MSR

| Check | Real | Spoofed |
|-------|------|---------|
| RDMSR from user-mode | Blocked by Windows | Blocked (kernel only) |
| XGETBV XCR0 | `0x7` (X87+SSE+AVX) | `0x7` |

**Result:** MSRs are kernel-protected on Windows. Engine patches RDMSR/WRMSR instructions if found in the target `.text` segment.

---

## 4. KUSER_SHARED_DATA

| Offset | Field | Real | Spoofed |
|--------|-------|------|---------|
| `0x0262` | NtBuildNumber | Build-dependent | Spoofed to profile |
| `0x02D4` | KdDebuggerEnabled | `0x0` | `0x0` (clean) |
| `0x0318` | SystemTime | Real time | Spoofed |
| `0x0328` | InterruptTime | Real | Spoofed |
| `0x0348` | TickCountQuad | Real | Spoofed |
| `0x0370` | QPC value | Real | Spoofed |
| `0x0260` | NtMajorVersion | `10` | `10` |

**Result:** KUSER page is memory-protected by kernel; engine uses EPT hook (WHP) or shared memory overlays (VEH fallback).

---

## 5. Syscalls

| Syscall | Class | Real | Spoofed |
|---------|-------|------|---------|
| NtQuerySystemInformation | `0x23` (KdDebugger) | Enabled=N, NotPresent=Y | Enabled=N, NotPresent=Y |
| NtQuerySystemInformation | `0x67` (CodeIntegrity) | DSE enabled | DSE disabled |
| NtQuerySystemInformation | `0x0B` (ModuleInfo) | Large module list | Empty (4 bytes) |
| NtQueryInformationProcess | `0x07` (DebugPort) | No debugger | No debugger |
| NtQueryInformationProcess | `0x1E` (DebugObject) | No debug object | No debug object |

**Result:** Syscall replies are fully controlled by SoGen emulator. Code integrity, kernel debugger, module list, and process debug flags are all spoofed.

---

## 6. PEB

| Offset | Field | Real | Spoofed |
|--------|-------|------|---------|
| `PEB+0x0B8` | Process flags | `0x4` | `0x4` |
| `PEB+0x118` | ProcessParameters | Valid pointer | Valid pointer |
| `PEB+0x130` | BeingDebugged | `0x0` | `0x0` |

**Result:** PEB structure masked via SoGen.

---

## 7. Registry / File I/O

| Check | Real | Spoofed |
|-------|------|---------|
| `PhysicalDrive0` open | Accessible | BLOCKED by kernel32_proxy |
| `HKLM\HARDWARE\DESCRIPTION\System` | Accessible | Accessible (spoofed) |
| Volume serial | Real serial | Spoofed |
| Computer name | Real hostname | Spoofed |

**Result:** Registry queries return spoofed values. Physical drive access blocked. Volume serial spoofed.

---

## 8. WMI

| Property (Win32_Processor) | Real | Spoofed |
|----------------------------|------|---------|
| Name | i7-4510U | Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz |
| NumberOfCores | 2 | 10 |
| NumberOfLogicalProcessors | 4 | 20 |
| MaxClockSpeed | 2000 | 3700 |
| Manufacturer | GenuineIntel | GenuineIntel |
| Architecture | 9 (x64) | 9 (x64) |
| ProcessorId | Real | Spoofed |

**Result:** 12 Win32_Processor properties spoofed via wbem_proxy COM shim.

---

## 9. Consistency Checks

| Cross-check | Result |
|-------------|--------|
| CPUID leaf 0x1 EAX vs KUSER NtBuildNumber | Consistent |
| CPUID brand string vs registry brand string | Consistent (both "i9-10900K") |

**Result:** No cross-layer inconsistencies detected.

---

## Summary

| Area | Vector Count | Spoofable |
|------|-------------|-----------|
| CPUID | 5 leaf groups | ✅ Full |
| Timing | 4 checks | ✅ Full |
| MSR | 2 checks | ✅ (where patchable) |
| KUSER | 8 fields | ✅ Full |
| Syscalls | 6 classes | ✅ Full |
| PEB | 3 offsets | ✅ Full |
| Registry/File | 4 checks | ✅ Full |
| WMI | 12 properties | ✅ Full |
| Cross-layer | 2 checks | ✅ Consistent |
| **Total** | **20 vectors** | **All spoofed** |
