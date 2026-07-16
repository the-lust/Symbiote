# Symbiote

**Ring-3 Windows userspace hardware fingerprint interception and analysis framework — educational / security research**

Symbiote is a research platform for studying how Windows applications observe hardware and system configuration through CPUID, MSR, KUSER_SHARED_DATA, WMI, registry, syscall interfaces, and timing sources. It intercepts these queries using Microsoft's **Windows Hypervisor Platform (WHP)** as an execution backend, with **EPT process migration** for transparent guest execution inside a Hyper-V VCPU, **LSTAR→HLT syscall interception with host ntdll forwarding**, **proxy DLLs with IAT/EAT patching**, **VEH-assisted fallback handlers**, **BEL multi-VCPU architecture**, **EPT-based execution hook system**, **GPU DXVK passthrough**, and **WHP state snapshot/restore**.

> **WARNING: Educational / security research only.**

---

## Quick Start

```bat
git clone https://github.com/the-lust/Symbiote
cd Symbiote
cmake --preset msvc-x64
cmake --build --preset msvc-x64
```

---

## Project Structure

```
symbiote/
├── CMakeLists.txt                # Multi-arch build (MSVC x64/x86, MinGW), 23 targets
├── CMakePresets.json             # 6 build presets (MSVC Release/Debug x64/x86, MinGW x64/x86)
├── LICENSE
├── .gitignore
├── config/
│   ├── config.ini                # Active profile + feature toggles
│   ├── config.example.ini        # Example configuration
│   └── capture.ini               # Capture mode (all interception disabled)
├── docs/
│   ├── ARCHITECTURE.md           # Architecture overview
│   ├── TECHNIQUES.md             # Per-vector analysis deep dives
│   ├── RESULTS.md                # Real vs spoofed comparison
│   └── RESEARCH.md               # Research areas and future directions
├── scripts/
│   └── build.bat                 # Build helper
├── tools/
│   ├── handshake_test/           # CPUID handshake protocol test
│   ├── capture/                  # Standalone fingerprint capture tool
│   ├── msr_reader/               # MSR register reader
│   └── test_sections.ps1         # Section-by-section test script
└── src/
    ├── launcher/                 # launcher.exe — CLI arg parsing, process creation, engine injection
    ├── engine/                   # engine.dll — core engine (WHP, emulation, proxy, handlers)
    │   ├── whp/                  # WHP partition, page tables, VCPU, handlers
    │   ├── kernel/               # MinimalKernel (syscall dispatcher), SystemProfile, KernelBackend
    │   ├── emu/                  # Syscall emulators: Process, Memory, File, Registry, Timing, etc.
    │   ├── proxy/                # IatPatch, InlineHook, GpuBridge, DxvkIntegration, SyscallBridge
    │   ├── profile/              # GpuProfile, StorageProfile, TimingProfile
    │   ├── capture/              # CaptureLogger (TSV structured logging)
    │   ├── log/                  # Logger subsystem
    │   └── util/                 # HwDetect (TSC frequency, CPU vendor/feature detection)
    ├── proxydlls/                # 13 proxy DLL shims
    │   └── shared/               # ProxyExport.h
    ├── verify/                   # verify.exe — 9-phase test suite
    └── engine/                   # (engine DLL entry points)
```

---

## Components

| Component | File(s) | Role |
|-----------|---------|------|
| **launcher.exe** | `src/launcher/` | CLI: creates target suspended, injects engine.dll, calls Engine_Init, intercepts entry point, resumes |
| **engine.dll** | `src/engine/` | Core engine — WHP partition, VcpuManager, IAT/EAT patching, syscall forwarding, all handlers |
| **Partition** | `whp/Partition.cpp/.h` | WHP partition lifecycle: Create, SetupCpuCount, SetupMemory, SetupCpuidResultList, Init |
| **GuestPageTable** | `whp/GuestPageTable.cpp/.h` | Builds 4-level identity-mapped page tables |
| **VcpuManager** | `whp/VcpuManager.cpp/.h` | VCPU lifecycle, BootstrapFromContext, LSTAR→HLT syscall dispatch |
| **SyscallDispatch** | `whp/SyscallDispatch.cpp/.h` | Syscall number detection, BuildForwardTable, ForwardSyscall |
| **CpuidHandler** | `whp/CpuidHandler.cpp/.h` | CPUID exit handler — all standard/extended leaves, brand string |
| **RdtscHandler** | `whp/RdtscHandler.cpp/.h` | RDTSC/RDTSCP exit handler |
| **MsrHandler** | `whp/MsrHandler.cpp/.h` | MSR read/write exit handler |
| **EptHook** | `whp/EptHook.cpp/.h` | EPT violation handler |
| **KuserHook** | `whp/KuserHook.cpp/.h` | KUSER_SHARED_DATA VEH-based overlay (non-WHP fallback) |
| **KuserSync** | `whp/KuserSync.cpp/.h` | KUSER_SHARED_DATA WHP synchronization thread |
| **MagicCpuid** | `whp/MagicCpuid.cpp/.h` | 15-leaf CPUID handshake protocol (gated, default off) |
| **Canary** | `whp/Canary.cpp/.h` | Guard-page memory scanner detector |
| **AllocTracker** | `whp/AllocTracker.cpp/.h` | Monitors JIT/allocated memory via guard pages |
| **TimingCoordinator** | `whp/TimingCoordinator.h` | Cross-handler RDTSC→CPUID→RDTSC pattern detection |
| **SystemSpoofer** | `whp/SystemSpoofer.cpp/.h` | VEH-based interception of SGDT/SIDT/SLDT/STR/XGETBV (gated, default off) |
| **EptExecHook** | `whp/EptExecHook.cpp/.h` | EPT-based execution hook system |
| **WatchdogTracker** | `whp/WatchdogTracker.cpp/.h` | Threaded integrity watchdog detection |
| **EptSplitView** | `whp/EptSplitView.cpp/.h` | Per-VCPU memory view switching |
| **KernelLock (BEL)** | `whp/KernelLock.cpp/.h` | CRITICAL_SECTION-based mutex |
| **Snapshot** | `whp/Snapshot.cpp/.h` | Full WHP state serialization with file I/O and restore |
| **DxvkIntegration** | `proxy/DxvkIntegration.cpp/.h` | DXVK passthrough |
| **ThreadScheduler** | `whp/ThreadScheduler.cpp/.h` | Round-robin multi-VCPU coordinator |
| **ExitDispatcher** | `whp/ExitDispatcher.cpp/.h` | WHP exit reason dispatch routing |
| **ExceptionHandler** | `whp/ExceptionHandler.cpp/.h` | WHP VP exception handling |
| **MinimalKernel** | `kernel/MinimalKernel.cpp/.h` | Unified syscall dispatcher |
| **SystemProfile** | `kernel/SystemProfile.cpp/.h` | CPU profile data |
| **KernelBackend** | `kernel/KernelBackend.cpp/.h` | IKernelBackend implementation |
| **ProcessEmu** | `emu/ProcessEmu.cpp/.h` | Process-related syscall emulation |
| **MemoryEmu** | `emu/MemoryEmu.cpp/.h` | Memory-related syscall emulation |
| **FileEmu** | `emu/FileEmu.cpp/.h` | File system spoofing |
| **RegistryEmu** | `emu/RegistryEmu.cpp/.h` | Registry spoofing |
| **TimingEmu** | `emu/TimingEmu.cpp/.h` | Timing-related syscall emulation |
| **CryptoEmu** | `emu/CryptoEmu.cpp/.h` | Crypto-related syscall emulation |
| **ThreadManager** | `emu/ThreadManager.cpp/.h` | Thread lifecycle emulation |
| **SectionEmu** | `emu/SectionEmu.cpp/.h` | Section object emulation |
| **ObjectEmu** | `emu/ObjectEmu.cpp/.h` | Object handle emulation |
| **VirtualState** | `emu/VirtualState.cpp/.h` | Virtual state management |
| **PeLoader** | `emu/PeLoader.cpp/.h` | PE loading emulation |
| **IatPatch** | `proxy/IatPatch.cpp/.h` | IAT and EAT patching |
| **InlineHook** | `proxy/InlineHook.cpp/.h` | 12-byte jmp hooks with instruction decoder |
| **GpuBridge** | `proxy/GpuBridge.cpp/.h` | GPU DLL passthrough |
| **ModuleCloak** | `proxy/ModuleCloak.cpp/.h` | Module PEB/LDR hiding |
| **SyscallBridge** | `proxy/SyscallBridge.cpp/.h` | Syscall forwarding bridge |
| **ApiSetResolver** | `proxy/ApiSetResolver.cpp/.h` | ApiSet schema parser from PEB |
| **CaptureLogger** | `capture/CaptureLogger.cpp/.h` | Structured tab-separated capture log |
| **GpuProfile** | `profile/GpuProfile.cpp/.h` | GPU identity profile |
| **StorageProfile** | `profile/StorageProfile.cpp/.h` | Storage device profile |
| **HwDetect** | `util/HwDetect.h` | TSC frequency / CPU vendor detection |
| **ThreadHider** | `emu/ThreadHider.cpp/.h` | Thread enumeration filtering |
| **StackSpoofer** | `emu/StackSpoofer.cpp/.h` | Return-address redirection |
| **IndirectSyscall** | `whp/IndirectSyscall.cpp/.h` | EPT execute-disable on ntdll syscall page |
| **ConsistencyVerifier** | `whp/ConsistencyVerifier.cpp/.h` | 11 consistency checks |
| **SyscallTables** | `whp/SyscallTables.cpp/.h` | Static SSN tables |
| **AcpiTimerHandler** | `whp/AcpiTimerHandler.cpp/.h` | Synthetic ACPI PM timer and HPET counter |
| **Proxy DLLs** (13) | `proxydlls/*/` | IAT/EAT interceptors with clean DLL names |
| **verify.exe** | `src/verify/` | 9-phase test suite |

---

## Build

### Prerequisites

- Windows 10/11 x64 with Visual Studio 2022 C++ workload
- CMake 3.20+
- Windows SDK (includes `WinHvPlatform.h` / `WinHvPlatform.lib`)

### Presets

| Preset | Arch | Config | Compiler |
|--------|------|--------|----------|
| `msvc-x64` | x64 | Release | MSVC |
| `msvc-x64-debug` | x64 | Debug | MSVC |
| `msvc-x86` | x86 | Release | MSVC |
| `msvc-x86-debug` | x86 | Debug | MSVC |
| `mingw-x64` | x64 | Release | MinGW |
| `mingw-x86` | x86 | Release | MinGW |

### Build Commands

```bat
cmake --preset msvc-x64
cmake --build --preset msvc-x64
```

### Build Helper

`scripts\build.bat` accepts flags: `debug`, `x86`, `x86-debug`, `mingw`, `mingw-x64`.

### Output

All binaries go to `build/<preset>/bin/Release` (or `Debug`).

---

## Configuration

Default: `config/config.ini` (relative to launcher binary).

### Feature Toggles

```ini
[hypervisor_hiding]  alloc_tracker = false  ; AllocTracker (off by default)
[hypervisor_hiding]  system_spoofer = false ; SystemSpoofer VEH (off by default)
[system_spoofer]     enabled = false
[eat]                enabled = true         ; EAT patching
[watchdog]           enabled = true         ; Integrity watchdog detection
[ept_split_view]     enabled = true         ; EPT split-view
[forwarding]         enabled = true         ; Syscall forwarding
[stack_spoofer]      enabled = true         ; StackSpoofer
[indirect_syscall]   enabled = false        ; IndirectSyscall
[snapshot]           enabled = false        ; Snapshot
[cpuid]              status = 0             ; CPUID interception
[rdtsc]              status = 0             ; RDTSC interception
[msr]                status = 1             ; MSR interception
[kuser]              status = 1             ; KUSER_SHARED_DATA interception
[process]            status = 1             ; Process info interception
[registry]           status = 1             ; Registry interception
[file]               status = 1             ; File interception
[timing]             status = 1             ; Timing interception
[magic]              status = 0             ; MagicCpuid handshake
[vm]                 cpu_count = 2          ; Virtual CPU count
```

### Capture Mode

To log all fingerprint queries without interception (for analysis):

```bat
copy config\capture.ini config\config.ini
launcher.exe --target C:\Path\to\target.exe
```

---

## License

This project is open source for fair usage and educational study.

See `LICENSE` for full terms.
