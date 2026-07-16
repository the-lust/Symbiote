# Symbiote — Research Areas

## 1. WHP-Based Hardware Virtualization

The Windows Hypervisor Platform (WHP) provides a userspace API to Hyper-V VMX/SVM virtualization capabilities. Symbiote uses WHP to:

- Create a lightweight sidecar VM partition
- Intercept CPUID, RDTSC/RDTSCP, and MSR accesses via VM exits
- Map physical pages (EPT) for KUSER_SHARED_DATA interception
- Operate entirely from Ring 3 with no kernel driver

## 2. Vectored Exception Handling (VEH) Fallback

When WHP is unavailable, VEH provides instruction-level interception:

- CodePatcher overwrites CPUID/RDTSC/MSR instructions with UD2
- VEH handler catches #UD exceptions, emulates the instruction
- Guard-page VEH catches first access to allocated (JIT) memory pages

## 3. IAT/EAT Patching

Proxy DLLs intercept API calls at the import/export table level:

- 13 proxy DLLs with clean system DLL names (kernel32, ntdll, advapi32, etc.)
- IAT patching redirects imports to proxy functions
- EAT patching redirects exports to proxy functions
- Bound import and delay-load import handling
- ApiSet-aware DLL name resolution

## 4. Inline Hooks

12-byte `mov rax, imm64; jmp rax` hooks with instruction decoder for trampoline generation.

## 5. MSR Shadowing

Model-Specific Register access interception via WHP exit handlers. Configurable return values for known MSR indices.

## 6. KUSER_SHARED_DATA Analysis

The KUSER_SHARED_DATA page at `0x7FFE0000` contains system-wide shared data. Interception via EPT (WHP) or shared memory overlay (VEH) allows observation of which fields protection systems read.

## 7. Anti-Detection Research (Defensive)

### Observed Detection Vectors

- **CPUID 0x40000000**: Hypervisor presence detection via vendor string
- **EPT hook timing**: Timing side-channel through EPT-mapped pages
- **RDTSC/CPUID/RDTSC deltas**: VM-exit overhead measurement
- **Memory pattern scanning**: Detection of guard pages and hooks
- **Registry artifacts**: Hyper-V service keys and BIOS information
- **WMI queries**: Win32_Processor, Win32_ComputerSystem, SMBIOS

### Mitigation Techniques Studied

Each of these detection vectors has corresponding mitigation approaches documented in the codebase, configurable through feature toggles.

## 8. Multi-VCPU Architecture (BEL)

The Big Emulator Lock pattern serializes emulator state access across VCPUs while allowing parallel guest execution.

## 9. Per-VCPU Memory Views

EPT split-view provides per-VCPU memory visibility control for analyzing process isolation behaviors.

## 10. Fingerprint Capture Mode

Passive capture mode logs all fingerprint queries without modification for analysis and profile creation.

## 11. Related Academic Work

- Hypervisor-based introspection techniques
- Ring-3 only virtualization using WHP API
- Timing side-channel analysis in virtualized environments
- IAT/EAT interception for API monitoring
