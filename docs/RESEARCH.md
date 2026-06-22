# Genjutsu — External Research & Influence Map

## 1. momo5502/sogen (v4.5+)

- **Stars:** ~3100
- **URL:** https://github.com/momo5502/sogen
- **Backends:** Unicorn Engine, icicle-emu, WHP API
- **Key Features:**
  - Syscall-level emulation — intercepts Nt*/Zw* at the syscall boundary
  - Real system DLL loading (ntdll, kernel32 from the host)
  - Python bindings for scripting emulation scenarios
  - State snapshot/restore (serialization)
  - GDB protocol stub for debugging emulated code
  - Multi-architecture (x86, x64, ARM64 via Unicorn)

- **Relevance to Genjutsu:**
  - SoGen's syscall dispatch pattern directly inspired `sogen/SyscallDispatcher.cpp` and `sogen/SyscallNames.cpp`
  - Real DLL loading approach (from system32) is used in our proxy DLLs (`GetRealNtdll()` loads from system32)
  - WHP backend integration pattern shows how to blend VEH + WHP + syscall emulation
  - State serialization would allow Genjutsu to snapshot/restore emulated environments

- **Action Items for Genjutsu:**
  - Consider adding Python bindings to enable scripting of spoof profiles
  - Evaluate GDB protocol integration for debugging target processes under emulation
  - Add state serialization to VirtualState for snapshot/restore

## 2. x86matthew/WinVisor

- **Stars:** ~666
- **URL:** https://github.com/x86matthew/WinVisor
- **Key Features:**
  - WHP-based user-mode hypervisor
  - Process address space cloning (clone a process into an isolated VM)
  - Full PEB/TEB/KUSER_SHARED_DATA management via EPT
  - Syscall forwarding (intercept syscalls and route to emulated kernel)
  - Minimal attack surface — no driver, pure Ring-3

- **Relevance to Genjutsu:**
  - WinVisor's EPT-based KUSER management directly influenced `whp/KuserSync.cpp` and `whp/EptHook.cpp`
  - Process cloning concept maps to `sogen/ProcessEmu.cpp` virtual process list
  - Syscall forwarding pattern used in `proxy/SoGenBridge.cpp` and `sogen/SyscallDispatcher.cpp`
  - WHP partition setup code in `whp/Partition.cpp` follows WinVisor conventions

- **Action Items for Genjutsu:**
  - Implement full process address space cloning (clone target into WHP sidecar)
  - Add TEB emulation for thread-local storage spoofing
  - Evaluate WinVisor's APIC/IOAPIC handling for advanced MSI interrupts

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

- **Relevance to Genjutsu:**
  - WHP is our primary hardware virtualization backend
  - Code in `whp/` directly wraps all these APIs
  - Exit dispatcher (`ExitDispatcher.cpp`) routes exit types to handlers
  - EPT hooks (`EptHook.cpp`) manage GPA mapping for KUSER page

## 4. Other Related Projects

### a) hat's HyperKD / SimpleSVM
- **Location:** `D:\emu\hatsune-miku-hv-*`
- Provides reference fingerprint profile values (i9-10900K, Z490, RX 6800 XT)
- Uses kernel driver with SVM/VMX — Genjutsu differs by staying in Ring 3 via WHP

### b) Sandboxie / Sandbox
- **Relevance:** Process isolation via DLL injection + API hooking
- Comparison: Genjutsu's proxy DLL model is similar but extends to WHP + syscall emulation

### c) Hyper-V Platform (Type 2)
- WHP sits above Hyper-V's hypervisor (Ring -1)
- No need for custom drivers — Microsoft handles the ring transitions
- Degraded mode (VEH + IAT only) works when Hyper-V is unavailable

## 5. Future Research Directions

| Direction | Source | Benefit |
|-----------|--------|---------|
| Python bindings | sogen | Scriptable spoof profiles |
| State serialization | sogen | Snapshot/restore emulated env |
| Process cloning | WinVisor | Full process isolation |
| GDB protocol | sogen | Debug emulated processes |
| Multi-WHP partition | research | Sidecar + main process isolation |
| ARM64 emulation | Unicorn (sogen) | Cross-arch emulation |

## 6. Known Anti-Detection Patterns (Defensive)

Based on Denuvo-Research and WHP debugging:

| Detection | Genjutsu Mitigation | Risk Level |
|-----------|---------------------|------------|
| CPUID 0x40000000 (hypervisor leaf) | MagicCpuid hides Hyper-V presence | Medium |
| EPT hook timing | RDTSC spoofing + noise injection | Low |
| WHP module enumeration | KuserHook hides WHP artifacts | Medium |
| Driver enumeration | Empty module list in NtQuerySystemInformation | Low |
| Debugger detection | ProcessDebugPort/Flags/Handle spoofing | Low |
| VEH handler presence | Stack trace analysis not addressed | High |
| Timing correlation attacks | TSC noise + offset (configurable) | Medium |
