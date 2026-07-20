# Symbiote

**Ring-3 Windows userspace hypervisor framework — educational / security research**

Symbiote is a research hypervisor that runs a target process inside a Hyper-V VCPU created via Microsoft's **Windows Hypervisor Platform (WHP)**, intercepting every CPUID, MSR, RDTSC, syscall, memory access, and exception the target generates. It combines WHP's hardware virtualization with user-mode proxy DLLs, syscall emulation, and comprehensive feature masking to study how Windows applications observe their execution environment.

> **WARNING: Educational / security research only. Not for anti-cheat bypass or DRM circumvention.**

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Host Process                         │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  engine.dll                                           │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐ │  │
│  │  │WhpBackend│  │Unicorn   │  │ICpuBackend (abstract)│ │  │
│  │  │(primary) │  │Backend   │  │(fallback)            │ │  │
│  │  └────┬─────┘  │(fallback)│  └──────────────────────┘ │  │
│  │       │        └──────────┘                           │  │
│  │  ┌────┴─────────────────────────────────────────────┐ │  │
│  │  │  WHP Partition                                   │ │  │
│  │  │  ┌────────────────┐  ┌─────────────────────────┐ │ │  │
│  │  │  │  EptMemoryMgr  │  │  GuestPageTable         │ │  │ │
│  │  │  │  (on-demand    │  │  (4-level identity-map) │ │  │ │
│  │  │  │   EPT paging)  │  └─────────────────────────┘ │  │ │
│  │  │  └────────────────┘                              │  │ │
│  │  │  ┌────────────────┐  ┌─────────────────────────┐ │  │ │
│  │  │  │  VcpuManager   │  │  WhpHiding              │ │  │ │
│  │  │  │  (LSTAR→HLT    │  │  (13+ detection vectors │ │  │ │
│  │  │  │   syscall      │  │   countermeasures)      │ │  │ │
│  │  │  │   intercept)   │  └─────────────────────────┘ │  │ │
│  │  │  └───────┬───────┘                               │  │ │
│  │  │          │ Dispatch                              │  │ │
│  │  │  ┌───────┴─────────────────────────────────────┐ │  │ │
│  │  │  │  ExitDispatcher                             │ │  │ │
│  │  │  │  ┌──────────┐ ┌──────────┐ ┌──────────────┐ │ │  │ │
│  │  │  │  │CpuidHdlr │ │MsrHandler│ │RdtscHandler  │ │ │  │ │
│  │  │  │  │(mask+    │ │(spoof+   │ │(consistent   │ │ │  │ │
│  │  │  │  │ spoof)   │ │ hide)    │ │ TSC)         │ │ │  │ │
│  │  │  │  └──────────┘ └──────────┘ └──────────────┘ │ │  │ │
│  │  │  │  ┌──────────┐ ┌──────────┐ ┌──────────────┐ │ │  │ │
│  │  │  │  │EptExec   │ │System    │ │Exception     │ │ │  │ │
│  │  │  │  │Hook      │ │Spoofer   │ │Handler       │ │ │  │ │
│  │  │  │  └──────────┘ └──────────┘ └──────────────┘ │ │  │ │
│  │  │  └─────────────────────────────────────────────┘ │  │ │
│  │  │  ┌─────────────────────────────────────────────┐ │  │ │
│  │  │  │  ProcessCloner (WinVisor process migration) │ │  │ │
│  │  │  │  Snapshot (sub-ms VCPU state save/restore)  │ │  │ │
│  │  │  │  ReplayLogger (deterministic record/replay) │ │  │ │
│  │  │  │  GdbStub (remote debug over TCP :1234)      │ │  │ │
│  │  │  └─────────────────────────────────────────────┘ │  │ │
│  │  └────────────────────────────────────────────────┘ │  │ |
│  │                                                     │  │ |
│  │  ┌───────────────────────────────────────────────┐  │  │ |
│  │  │  MinimalKernel — unified syscall dispatcher   │  │  │ |
│  │  │  (ProcessEmu, MemoryEmu, FileEmu, RegistryEmu │  │  │ |
│  │  │   TimingEmu, CryptoEmu, ThreadManager, ...)   │  │  │ |
│  │  └───────────────────────────────────────────────┘  │  │ |
│  │                                                     │  │ |
│  │  ┌───────────────────────────────────────────────┐  │  │ |
│  │  │  Proxy DLLs (13) — IAT/EAT hooks: ntdll.dll,  │  │  │ |
│  │  │  kernel32.dll, kernelbase.dll, advapi32.dll,  │  │  │ |
│  │  │  user32.dll, wbem.dll, wtsapi32.dll,          │  │  │ |
│  │  │  secur32.dll, crypt32.dll, winhttp.dll,       │  │  │ |
│  │  │  dnsapi.dll, iphlpapi.dll, ws2_32.dll         │  │  │ |
│  │  └───────────────────────────────────────────────┘  │  │ |
│  │                                                     │  │ |
│  │  ┌───────────────────────────────────────────────┐  │  │ |
│  │  │  GpuBridge → ForwardVulkanIcd — real Vulkan   │  │  │ |
│  │  │  ICD passthrough via VK_ICD_FILENAMES         │  │  │ |
│  │  └───────────────────────────────────────────────┘  │  │ |
│  └────────────────────────────────────────────────────────┘ │
│                                                             │
│  launcher.exe — CLI, injects engine.dll into target,        │
│  calls Engine_Init, intercepts entry point                  │
└─────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

| Principle | Implementation |
|-----------|---------------|
| **No INT3 trampolines** | All syscall interception via LSTAR→HLT exclusively — zero `0xCC` writes to executable memory (page hashes never change) |
| **No artificial timing jitter** | JitterDelay() removed from CPUID/MSR handlers — no statistically detectable timing patterns on VM exits |
| **Real system DLLs in guest** | Sogen approach — 13 proxy DLLs forward real system DLL calls, reimplement only what must be spoofed |
| **CPU backend abstraction** | `ICpuBackend` interface: `WhpBackend` (primary, WHP hardware) + `UnicornBackend` (fallback, software-only) |
| **WHP hiding is multi-layer** | 13+ detection vectors covered: CPUID bits, hypervisor leaves, MSR range, RDTSC/RDTSCP timing, Red Pill, SIDT/SGDT/SLDT/STR, ACPI timers, topology, EPT scanning, cache/TLB |
| **Process migration** | WinVisor-style — clone target process memory directly into guest via identity-mapped EPT, no kernel driver needed |
| **BEL architecture** | Global exclusive lock (CriticalSection) + per-VCPU shared access for handler thread safety |

## WHP Detection Countermeasures

| Vector | Protection | Module |
|--------|-----------|--------|
| CPUID leaf 1 ECX[31] (hypervisor bit) | Cleared to 0 | CpuidHandler + WhpHiding |
| CPUID 0x40000000-0x400000FF (hypervisor leaves) | All zeros | CpuidHandler + WhpHiding |
| CPUID 0x80000001 ECX[31] | Cleared to 0 | WhpHiding |
| MSR 0x40000000-0x40000FFF (Hyper-V range) | Returns 0 / #GP | MsrHandler + WhpHiding |
| RDTSC timing (CPUID→RDTSC delta) | Consistent TSC, no jitter | RdtscHandler + WhpHiding |
| RDTSCP (IA32_TSC_AUX VP index) | Returns 0 | WhpHiding |
| Red Pill (CR3 comparison) | CR3 reads return same value | WhpHiding |
| SIDT/SGDT/SLDT/STR behavior | EPT execution hook intercept | SystemSpoofer + EptExecHook |
| Cache/TLB topology leaves | Spoofed from real hardware | CpuidHandler |
| ACPI synthetic timer detection | Consistent timer values | AcpiTimerHandler |
| TSC frequency consistency | Matches CPUID leaf 0x15/0x16 | WhpHiding |
| Memory scanning for EPT hooks | No INT3 writes to host pages | All modules |
| Host process/module detection | ModuleCloak + ThreadHider | proxy + emu |

## Quick Start

```bat
git clone https://github.com/the-lust/Symbiote
cd Symbiote
cmake --preset msvc-x64
cmake --build --preset msvc-x64
```

Then run a target under the hypervisor:

```bat
launcher.exe --target C:\Windows\System32\notepad.exe
```

## Project Structure

```
symbiote/
├── CMakeLists.txt                # 22 targets, /W4 /WX (MSVC), configurable WHP/Unicorn
├── CMakePresets.json             # 6 build presets
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
    ├── launcher/                 # launcher.exe — CLI, process creation, engine injection
    ├── engine/                   # engine.dll — core hypervisor engine
    │   ├── whp/                  # WHP partition, VCPU, handlers, hiding
    │   ├── backend/              # ICpuBackend + WhpBackend + UnicornBackend
    │   ├── kernel/               # MinimalKernel (syscall dispatcher)
    │   ├── emu/                  # Syscall emulators (Process, Memory, File, Registry...)
    │   ├── proxy/                # IatPatch, InlineHook, GpuBridge, DxvkIntegration
    │   ├── profile/              # GpuProfile, StorageProfile
    │   ├── capture/              # CaptureLogger (TSV structured logging)
    │   ├── debug/                # GdbStub (remote debug over TCP)
    │   ├── replay/               # ReplayLogger (deterministic record/replay)
    │   ├── log/                  # Logger subsystem
    │   └── util/                 # HwDetect (TSC, CPU vendor detection)
    ├── proxydlls/                # 13 proxy DLL shims
    │   └── shared/               # ProxyExport.h
    └── verify/                   # verify.exe — 9-phase test suite
```

## Components

| Component | Location | Role |
|-----------|----------|------|
| **launcher.exe** | `src/launcher/` | CLI: creates target suspended, injects engine.dll, calls Engine_Init, registers entry intercept |
| **engine.dll** | `src/engine/` | Core engine — all hypervisor, emulation, proxy logic |
| **ICpuBackend** | `src/engine/backend/ICpuBackend.h` | Abstract CPU backend interface (run/stop/regs) |
| **WhpBackend** | `src/engine/backend/WhpBackend.cpp/.h` | Primary CPU backend — WHP hardware virtualization |
| **UnicornBackend** | `src/engine/backend/UnicornBackend.cpp/.h` | Fallback CPU backend — Unicorn1 emulation |
| **Partition** | `whp/Partition.cpp/.h` | WHP partition lifecycle, MapOnDemand |
| **GuestPageTable** | `whp/GuestPageTable.cpp/.h` | 4-level identity-mapped page tables |
| **VcpuManager** | `whp/VcpuManager.cpp/.h` | VCPU lifecycle, LSTAR→HLT syscall dispatch, multi-VCPU |
| **SyscallDispatch** | `whp/SyscallDispatch.cpp/.h` | Syscall number detection, BuildForwardTable, host ntdll forwarding |
| **SyscallTables** | `whp/SyscallTables.cpp/.h` | Static SSN tables (no runtime NtQuerySystemInformation) |
| **CpuidHandler** | `whp/CpuidHandler.cpp/.h` | CPUID exit handler — all standard/extended leaves, hypervisor masking |
| **RdtscHandler** | `whp/RdtscHandler.cpp/.h` | RDTSC/RDTSCP exit handler with consistent timing |
| **MsrHandler** | `whp/MsrHandler.cpp/.h` | MSR read/write exit handler — Hyper-V range hidden |
| **WhpHiding** | `whp/WhpHiding.cpp/.h` | Comprehensive WHP detection countermeasures (13+ vectors) |
| **EptHook** | `whp/EptHook.cpp/.h` | EPT violation handler (kernel memory, MSR bitmap) |
| **EptExecHook** | `whp/EptExecHook.cpp/.h` | EPT-based execution hook with single-step |
| **EptMemoryManager** | `whp/EptMemoryManager.cpp/.h` | On-demand EPT page-in with LRU eviction |
| **EptSplitView** | `whp/EptSplitView.cpp/.h` | Per-VCPU memory view switching |
| **EptPageProtect** | `whp/EptPageProtect.cpp/.h` | EPT page permission hooks |
| **SystemSpoofer** | `whp/SystemSpoofer.cpp/.h` | EPT-based SGDT/SIDT/SLDT/STR/XGETBV interception |
| **KuserSync** | `whp/KuserSync.cpp/.h` | KUSER_SHARED_DATA WHP sync thread |
| **KuserHook** | `whp/KuserHook.cpp/.h` | KUSER_SHARED_DATA VEH overlay (non-WHP fallback) |
| **MagicCpuid** | `whp/MagicCpuid.cpp/.h` | 15-leaf CPUID handshake protocol (gated) |
| **TimingCoordinator** | `whp/TimingCoordinator.cpp/.h` | Cross-handler RDTSC→CPUID→RDTSC pattern detection |
| **AcpiTimerHandler** | `whp/AcpiTimerHandler.cpp/.h` | Synthetic ACPI PM timer + HPET counter |
| **IndirectSyscall** | `whp/IndirectSyscall.cpp/.h` | EPT execute-disable on ntdll syscall page |
| **KernelLock (BEL)** | `whp/KernelLock.cpp/.h` | Global exclusive + per-VCPU shared SRW lock |
| **Snapshot** | `whp/Snapshot.cpp/.h` | Sub-ms VCPU+handler state save/restore (no file I/O) |
| **ConsistencyVerifier** | `whp/ConsistencyVerifier.cpp/.h` | Runtime consistency assertions (11 checks) |
| **ThreadScheduler** | `whp/ThreadScheduler.cpp/.h` | Round-robin multi-VCPU coordinator |
| **WatchdogTracker** | `whp/WatchdogTracker.cpp/.h` | Threaded integrity watchdog |
| **ExitDispatcher** | `whp/ExitDispatcher.cpp/.h` | WHP exit reason dispatch routing |
| **ExceptionHandler** | `whp/ExceptionHandler.cpp/.h` | WHP VP exception handler |
| **AllocTracker** | `whp/AllocTracker.cpp/.h` | Guard-page JIT memory monitor |
| **Canary** | `whp/Canary.cpp/.h` | Guard-page memory scanner detector |
| **VeSimulation** | `whp/VeSimulation.cpp/.h` | Virtual-Exemption simulation for EPT |
| **MinimalKernel** | `kernel/MinimalKernel.cpp/.h` | Unified syscall dispatcher + syscall emulator router |
| **SystemProfile** | `kernel/SystemProfile.cpp/.h` | CPU/vendor feature profile |
| **KernelBackend** | `kernel/KernelBackend.cpp/.h` | IKernelBackend implementation |
| **ProcessCloner** | `engine/ProcessCloner.cpp/.h` | WinVisor-style process memory snapshot into WHP guest |
| **GdbStub** | `debug/GdbStub.cpp/.h` | Remote GDB debug stub (TCP port 1234) |
| **ReplayLogger** | `replay/ReplayLogger.cpp/.h` | Deterministic record/replay of external inputs |
| **ProcessEmu** | `emu/ProcessEmu.cpp/.h` | Process-related syscall emulation |
| **MemoryEmu** | `emu/MemoryEmu.cpp/.h` | Memory-related syscall emulation |
| **FileEmu** | `emu/FileEmu.cpp/.h` | File system spoofing + Sandboxie redirection |
| **RegistryEmu** | `emu/RegistryEmu.cpp/.h` | Registry spoofing + Sandboxie virtualization |
| **TimingEmu** | `emu/TimingEmu.cpp/.h` | Timing-related syscall emulation |
| **CryptoEmu** | `emu/CryptoEmu.cpp/.h` | Crypto-related syscall spoofing |
| **ThreadManager** | `emu/ThreadManager.cpp/.h` | Thread lifecycle emulation |
| **ThreadHider** | `emu/ThreadHider.cpp/.h` | Thread enumeration filtering |
| **StackSpoofer** | `emu/StackSpoofer.cpp/.h` | Return-address redirection |
| **SectionEmu** | `emu/SectionEmu.cpp/.h` | Section object emulation |
| **ObjectEmu** | `emu/ObjectEmu.cpp/.h` | Object handle emulation |
| **VirtualState** | `emu/VirtualState.cpp/.h` | Virtual state management |
| **PeLoader** | `emu/PeLoader.cpp/.h` | PE loading emulation |
| **DeviceIoEmu** | `emu/DeviceIoEmu.cpp/.h` | Device IOCTL emulation |
| **IatPatch** | `proxy/IatPatch.cpp/.h` | IAT + EAT patching with ApiSet resolution |
| **InlineHook** | `proxy/InlineHook.cpp/.h` | 12-byte jmp hooks |
| **GpuBridge** | `proxy/GpuBridge.cpp/.h` | GPU DLL passthrough, ForwardVulkanIcd |
| **DxvkIntegration** | `proxy/DxvkIntegration.cpp/.h` | DXVK passthrough + Vulkan layer detection |
| **SyscallBridge** | `proxy/SyscallBridge.cpp/.h` | Syscall forwarding bridge |
| **ModuleCloak** | `proxy/ModuleCloak.cpp/.h` | Module hiding from PEB LDR lists |
| **ApiSetResolver** | `proxy/ApiSetResolver.cpp/.h` | ApiSet schema parser from PEB |
| **ProxyBase** | `proxy/ProxyBase.cpp/.h` | Common proxy DLL infrastructure |
| **Fallthrough** | `proxy/Fallthrough.cpp/.h` | Export fallthrough helper |
| **InstructionDecoder** | `proxy/InstructionDecoder.cpp/.h` | x86 instruction length decoder |
| **CaptureLogger** | `capture/CaptureLogger.cpp/.h` | Structured TSV capture log |
| **GpuProfile** | `profile/GpuProfile.cpp/.h` | GPU identity profile |
| **StorageProfile** | `profile/StorageProfile.cpp/.h` | Storage device profile |
| **HwDetect** | `util/HwDetect.h` | TSC frequency, CPU vendor/feature detection |
| **Proxy DLLs** (13) | `proxydlls/*/` | Real system DLL shims: ntdll, kernel32, kernelbase, advapi32, user32, wbem, wtsapi32, secur32, crypt32, winhttp, dnsapi, iphlpapi, ws2_32 |
| **verify.exe** | `src/verify/` | 9-phase test suite |

## Build

### Prerequisites

- Windows 10/11 x64 with Visual Studio 2022+ C++ workload
- CMake 3.20+
- Windows SDK (includes `WinHvPlatform.h` / `WinHvPlatform.lib`)
- Unicorn2 library (for UnicornBackend fallback)

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

All binaries go to `build/<preset>/bin/Release` (or `Debug`). 22 targets total, all compile clean with `/W4 /WX`.

## Configuration

Default: `config/config.ini` (relative to launcher binary).

```ini
[hypervisor_hiding]  alloc_tracker = false    ; AllocTracker (off by default)
[hypervisor_hiding]  system_spoofer = false   ; SystemSpoofer VEH (off by default)
[system_spoofer]     enabled = false
[eat]                enabled = true           ; EAT patching
[watchdog]           enabled = true           ; Integrity watchdog
[ept_split_view]     enabled = true           ; EPT split-view
[forwarding]         enabled = true           ; Syscall forwarding
[stack_spoofer]      enabled = true           ; StackSpoofer
[indirect_syscall]   enabled = false          ; IndirectSyscall
[snapshot]           enabled = false          ; Snapshot
[cpuid]              status = 0              ; CPUID interception
[rdtsc]              status = 0              ; RDTSC interception
[msr]                status = 1              ; MSR interception
[kuser]              status = 1              ; KUSER_SHARED_DATA interception
[process]            status = 1              ; Process info interception
[registry]           status = 1              ; Registry interception
[file]               status = 1              ; File interception
[timing]             status = 1              ; Timing interception
[magic]              status = 0              ; MagicCpuid handshake
[vm]                 cpu_count = 2           ; Virtual CPU count
```

### Capture Mode

To log all fingerprint queries without interception (for analysis):

```bat
copy config\capture.ini config\config.ini
launcher.exe --target C:\Path\to\target.exe
```

## Related Work

- **[Sogen](https://github.com/hedronium/Sogen)** (3.3k stars) — WHP+Unicorn+KVM backends, real system DLLs in guest, LSTAR→HLT syscall intercept, GDB stub, deterministic replay. Symbiote adopts the same CPU backend abstraction and real-DLL approach.
- **[WinVisor](https://github.com/ionescu007/winvisor)** (666 stars) — Process cloning directly into WHP guest via identity-mapped EPT. Symbiote's ProcessCloner implements the same technique.
- **[Sandboxie](https://github.com/sandboxie-plus/Sandboxie)** — User-mode API redirection for file, registry, process, and token isolation. Symbiote applies these patterns at the ntapi/kernel32 proxy DLL level.

## License

This project is open source for fair usage and educational study.

See `LICENSE` for full terms.
