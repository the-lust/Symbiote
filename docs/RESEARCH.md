# Symbiote — External Research & Influence Map

## 1. momo5502/sogen (v4.5+)

- **Stars:** ~3100
- **URL:** https://github.com/momo5502/sogen
- **Backends:** Unicorn Engine, icicle-emu, WHP API
- **Key Features:**
  - Syscall-level emulation — intercepts Nt*/Zw* at the syscall boundary
  - Real system DLL loading (ntdll, kernel32 from the host)
  - Python bindings for scripting emmulation scenarios
  - State snapshot/restore (serialzation)
  - GDB protocol stub for debugging emulated code
  - Multi-architecture (x86, x64, ARM64 via Unicorn)

- **Relevance to Symbiote:**
  - SoGen's syscall dispatch pattern directly inspired `sogen/SyscallDispatcher.cpp` and `sogen/SyscallNames.cpp`
  - Real DLL loading approach (from system32) is used in our proxy DLLs (`GetRealNtdll()` loads from system32)
  - WHP backend integration pattern shows how to blend VEH + WHP + syscall emmulation
  - State serialzation would allow Symbiote to snapshot/restore emulated enviroments

- **Action Items for Symbiote:**
  - Consider adding Python bindings to enable scripting of spoof profiles
  - Evaluate GDB protocol integration for debugging target processes under emulation
  - Add state serialization to VirtualState for snapshot/restore

## 3. Microsoft WHP API

- **Documentation:** https://learn.microsoft.com/en-us/virtualization/api/whp/
- **Key APIs:**
  - `WHvCreatePartition` — creates a hypervisor partition
  - `WHvSetupPartition` — commits partition configuration
  - `WHvCreateVirtualProcessor` — creates VCPUs
  - `WHvSetPartitionProperty` — configures partition
  - `WHvRunVirtualProcessor` — runs a VCPU (with exit context)
  - `WHvMapGpaRange` — maps guest physical address space
  - `WHvTranslateGva` — translates guest virtual to guest physical
  - `WHvGetVirtualProcessorRegisters` — reads VCPU state
  - `WHvSetVirtualProcessorRegisters` — writes VCPU state

- **Exit Types Handled:**
  - `WHvRunVpExitReasonMemoryAccess` — EPT violations
  - `WHvRunVpExitReasonX64Cpuid` — CPUID instructions
  - `WHvRunVpExitReasonX64MsrAccess` — RDMSR/WRMSR
  - `WHvRunVpExitReasonX64Rdtsc` — RDTSC/RDTSCP
  - `WHvRunVpExitReasonX64IoPortAccess` — I/O port access
  - `WHvRunVpExitReasonX64InterruptWindow` — interrupt delivery
  - `WHvRunVpExitReasonException` — exceptions (GP, UD, etc.)

- **Limitations (experienced):**
  - `WHvCreatePartition → 0xC0351000` on systems with VBS or without Hyper-V enabled
  - Cannot create WHP partition if Hyper-V is not active
  - Only one WHP partition per process
  - EPT hook granularity limited to 4KB pages
  - No support for nested virtualization

- **Relevance to Symbiote:**
  - WHP is our primary hardware virtualization backend
  - Code in `whp/` directly wraps all these APIs
  - Exit dispatcher (`ExitDispatcher.cpp`) routes exit types to handlers
  - EPT hooks (`EptHook.cpp`) manage GPA mapping for KUSER page

## 4. Other Related Projects

### a) hat's HyperKD / SimpleSVM
- Provides reference fingerprint profile values (i9-10900K, Z490, RX 6800 XT)
- Uses kernel driver with SVM/VMX — Symbiote differs by staying in Ring 3 via WHP

### b) Sandboxie / Sandbox
- **Relevance:** Process isolation via DLL injection + API hooking
- Comparison: Symbiote's proxy DLL model is similar but extends to WHP + syscall emulation

### c) Hyper-V Platform (Type 2)
- WHP sits above Hyper-V's hypervisor (Ring -1)
- No need for custom drivers — Microsoft handles the ring transitions
- Degraded mode (VEH + IAT only) works when Hyper-V is unavailable

## 5. Future Research Directions

| Direction | Source | Benefit |
|-----------|--------|---------|
| Python bindings | sogen | Scriptable spoof profiles |
| State serialization | sogen | Snapshot/restore emulated env |
| Process cloning | research | Full process isolation |
| GDB protocol | sogen | Debug emulated processes |
| Multi-WHP partition | research | Sidecar + main process isolation |
| ARM64 emulation | Unicorn (sogen) | Cross-arch emulation |

## 6. Known Anti-Detection Patterns (Defensive)

| Detection | Symbiote Mitigation | Risk Level |
|-----------|---------------------|------------|
| CPUID 0x40000000 (hypervisor leaf) | MagicCpuid hides Hyper-V presence | Medium |
| EPT hook timing | RDTSC spoofing + noise injection | Low |
| WHP module enumeration | KuserHook hides WHP artifacts | Medium |
| Driver enumeration | Empty module list in NtQuerySystemInformation | Low |
| Debugger detection | ProcessDebugPort/Flags/Handle spoofing | Low |
| VEH handler presence | Stack trace analysis not addressed | High |
| Timing correlation attacks | TSC noise + offset (configurable) | Medium |
