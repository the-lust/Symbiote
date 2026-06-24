# Symbiote — Research Areas

## 1. WHP-Based Hardware Virtualization

The Windows Hypervisor Platform (WHP) provides a userspace API to Hyper-V's
VMX/SVM virtualization capabilities. Symbiote uses WHP to:

- Create a lightweight sidecar VM partition
- Intercept CPUID, RDTSC/RDTSCP, and MSR accesses via VM exits
- Map spoofed physical pages (EPT) for KUSER_SHARED_DATA interception
- Operate entirely from Ring 3 with no kernel driver

## 2. Vectored Exception Handling (VEH) Fallback

When WHP is unavailable, VEH provides instruction-level interception:

- CodePatcher overwrites CPUID/RDTSC/MSR instructions with UD2
- VEH handler catches #UD exceptions, emulates the instruction with spoofed values
- Guard-page VEH catches first access to allocated (JIT) memory pages
- AllocTracker manages 50ms re-arm timer for decrypt→execute→re-encrypt cycles

## 3. IAT Patching & Proxy DLL Shims

13 proxy DLLs intercept IAT-bound API calls:

- ntdll, kernel32, kernelbase, advapi32, user32, wbem
- wtsapi32, secur32, crypt32, winhttp, dnsapi, iphlpapi, ws2_32
- Each forwards benign calls to the real system
- Sensitive calls route through engine.dll for spoofed responses

## 4. Inline Hooks & Syscall Emulation

InlineHook provides 12-byte `mov rax,imm64; jmp rax` hooks at function
prologues. The trampoline uses a table-driven x64 instruction decoder to
copy only complete instructions (covering ≥12 bytes). Hooked functions:

- NtQuerySystemInformation — spoofs kernel debugger, module list, CI policy
- NtQueryInformationProcess — spoofs debug port, flags, object handle

MinimalKernel owns all emulator instances (Process, Memory, File, Timing,
Registry, Crypto, Thread, Section, Object, VirtualState) and dispatches
syscalls via a static DispatchThunk.

## 5. MSR Shadowing & Stealth Model

- FEATURE_CONTROL returns 0x4 (locked, VMX=0, SMX=0, SGX=0)
- CPUID leaf 1 ECX[31] (hypervisor) and ECX[6] (SMX) masked
- IA32_VMX MSRs (0x480-0x493) cached at init; reads return real HW values
- Hyper-V TLFS MSRs (0x40000000-0x40000FFF): reads/writes inject #GP
- Timing jitter (0-200µs MSR, 0-500µs CPUID) masks VM exit side-channels

## 6. Anti-Detection Considerations (Defensive Research)

| Detection Vector | Mitigation |
|-----------------|------------|
| CPUID hypervisor leaf | Zeroed (0x40000000 range) |
| CPUID brand string | Config-driven via CpuidHandler + MagicCpuid enhanced mode |
| CPUID per-process tracking | MagicCpuid PID registration limits spoofing to target only |
| EPT hook timing | RDTSC spoofing + noise injection + TimingCoordinator delta normalization |
| RDTSC→CPUID→RDTSC delta | TimingCoordinator cross-handler pattern detection + 3 jitter strategies |
| WHP module presence | KuserHook hides artifacts |
| Driver enumeration | Empty module list in syscalls |
| Debugger detection | ProcessDebugPort/Flags/Handle clean |
| Memory scan detection | Canary guard-page VEH callback logs scans |
| VEH stack trace | Not addressed (high risk) |
| Timing correlation | TSC noise + offset (configurable) |
| Handshake protocol detection | Magic leaves only respond inside WHP partition; passthrough on bare metal |

## 7. Future Research Directions

- Python bindings for scriptable spoof profiles
- State serialization for snapshot/restore of emulated environments
- Process cloning for full execution isolation
- GDB protocol stub for debugging under emulation
- Multi-WHP partition for sidecar + main process isolation
