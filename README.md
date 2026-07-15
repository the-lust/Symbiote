# Symbiote

**Ring-3 Windows userspace hardware fingerprint spoofing framework — educational / security research**

Symbiote is a research platform for studying hardware fingerprinting techniques — intercepting and spoofing CPUID, MSR, KUSER_SHARED_DATA, WMI, registry, syscalls, and timing entirely from user mode **without kernel drivers**. It uses Microsoft's **Windows Hypervisor Platform (WHP)** as its execution backend, with **EPT process migration (Ghost Sandbox)** for transparent guest execution inside a Hyper-V VCPU, **LSTAR→HLT syscall interception with host ntdll forwarding**, **proxy DLLs with IAT/EAT patching**, and **config-gated VEH handlers** for descriptor-table queries and JIT memory.

> **WARNING: Educational / security research only.** This project exists to study hardware fingerprinting mechanisms.

---

## Quick Start

```bat
git clone https://github.com/the-lust/Symbiote
cd Symbiote
cmake --preset msvc-x64
cmake --build --preset msvc-x64
build\msvc\x64\bin\Release\launcher.exe --target C:\Path\to\target.exe
```

---

## Project Structure

```
symbiote/
├── CMakeLists.txt                # Multi-arch build (MSVC x64/x86, MinGW), 3+ targets, 13 proxy DLLs, 4 tools
├── CMakePresets.json             # 6 build presets (MSVC Release/Debug x64/x86, MinGW x64/x86)
├── LICENSE                       # Symbiote Fair Usage License
├── .gitignore
├── config/
│   ├── config.ini                # Active spoof profile (Dell i7-4510U) + feature toggles
│   ├── config.example.ini        # Example profile (i9-10900K + RX 6800 XT)
│   └── capture.ini               # Capture mode config (all spoofing disabled)
├── docs/
│   ├── ARCHITECTURE.md           # Architecture overview and design decisions
│   ├── TECHNIQUES.md             # Per-vector spoofing deep dives
│   ├── RESULTS.md                # Real vs spoofed comparison across 20 vectors
│   └── RESEARCH.md               # Research areas and future directions
├── scripts/
│   └── build.bat                 # Build helper (supports debug/x86/mingw flags)
├── tools/
│   ├── handshake_test/           # Magic CPUID handshake protocol verification
│   ├── capture/                  # Standalone fingerprint capture tool (5-min loop)
│   ├── msr_reader/               # MSR register reader (via semav6msr64 kernel driver)
│   └── test_sections.ps1         # Section-by-section bisect test script for game compatibility
└── src/
    ├── launcher/                 # launcher.exe — CLI arg parsing, suspended process creation,
    │                             #   engine.dll injection, Engine_Init, entry point interception
    ├── engine/                   # engine.dll — core engine (35 WHP files, 24 emu, 16 proxy, ...)
    │   ├── whp/                  # WHP partition, GuestPageTable, VcpuManager, SyscallDispatch,
    │   │                         #   CpuidHandler, RdtscHandler, MsrHandler, EptHook, KuserHook,
    │   │                         #   KuserSync, MagicCpuid, Canary, AllocTracker,
    │   │                         #   TimingCoordinator, SystemSpoofer, ThreadScheduler,
    │   │                         #   ExitDispatcher, ExceptionHandler
    │   ├── kernel/               # MinimalKernel (unified syscall dispatcher),
    │   │                         #   SystemProfile (CPU profiles), KernelBackend (bridge)
    │   ├── emu/                  # Syscall emulators: ProcessEmu, MemoryEmu, FileEmu, RegistryEmu,
    │   │                         #   TimingEmu, CryptoEmu, ThreadManager, SectionEmu, ObjectEmu,
    │   │                         #   VirtualState, PeLoader
    │   ├── proxy/                # IatPatch (IAT/EAT patching, restore), InlineHook (12-byte jmp),
    │   │                         #   GpuBridge (GPU DLL passthrough), ModuleCloak (PEB hiding),
    │   │                         #   SyscallBridge
    │   ├── profile/              # GpuProfile, StorageProfile (identity profiles for spoofing)
    │   ├── capture/              # CaptureLogger (structured TSV logging, 100MB auto-rotate)
    │   ├── log/                  # Logger subsystem (SYSLOG, SYSERR macros)
    │   └── util/                 # HwDetect (TSC frequency detection, CPU vendor/feature masking)
    ├── proxydlls/                # 13 proxy DLL shims with clean system names:
    │   │                         #   ntdll, kernel32, kernelbase, advapi32, user32, wbem,
    │   │                         #   wtsapi32, secur32, crypt32, winhttp, dnsapi, iphlpapi, ws2_32
    │   └── shared/               # ProxyExport.h (cross-arch export macro)
    ├── verify/                   # verify.exe — 9-phase spoof verification test suite
    └── engine/                   # (engine DLL entry points: DllMain, Engine_Init, Engine_VcpuEntry, ...)
```

---

## Architecture

Symbiote operates in two layers that work together transparently:

### Layer 1: Proxy DLLs + IAT/EAT Patching (always active)

13 proxy DLLs with clean system names are loaded early via `LoadLibraryW` with absolute paths. The engine patches the target's IAT (Import Address Table) and optionally EAT (Export Address Table) to route API calls through the engine before they reach the real system. Proxy DLLs cover: kernel32, ntdll, kernelbase, advapi32, user32, wbem (WMI), wtsapi32, secur32, crypt32, winhttp, dnsapi, iphlpapi, ws2_32.

`GetProcAddress` lookups are intercepted via a registered function table (`RegisterProxyFunctions`), avoiding name-based module lookup on renamed proxies.

### Layer 2: WHP Ghost Sandbox (when WHP available)

When Windows Hypervisor Platform is available, the engine creates a lightweight Hyper-V partition and migrates the target process into a WHP Virtual Processor (VCPU). Inside VMX non-root mode, all hardware fingerprinting instructions cause VM exits that the engine handles:

```
Target Process (Ring 3)
  Proxy DLLs (clean names)  ───┐
  kernel32, ntdll, ...          ├── IAT/EAT Patching → engine.dll
  wbem, ws2_32, ...             │       │
                                │       │
  ┌─────────────────────────────┘       │
  │   ┌──────────────────────────────────┘
  │   │
  │   Engine Thread:
  │   ├── Build GuestPageTable (4-level page tables, GPA=VA identity)
  │   ├── Create WHP Partition + VCPU #0
  │   ├── Signal EngineReady
  │   └── Idle (Sleep loop)
  │
  │   Game Main Thread:
  │   ├── Hits entry-point trampoline → Engine_VcpuEntry()
  │   ├── RtlCaptureContext → BootstrapFromContext()
  │   └── Enters WHP VCPU:
  │         ├── Custom CR3 = PML4 GPA (identity-mapped page tables)
  │         ├── LSTAR→HLT page (SYSCALL → VM exit via HLT)
  │         ├── WHV_RUN_VP loop:
  │         │     CPUID       → WHP exit   → CpuidHandler        → spoofed values
  │         │     RDTSC/RDTSCP→ WHP exit   → RdtscHandler        → spoofed TSC
  │         │     MSR R/W     → WHP exit   → MsrHandler           → spoofed MSRs
  │         │     HLT         → WHP exit   → HandleSyscallExit   → spoofed/forwarded
  │         │     Mem fault   → WHP exit   → MapDynamicPage       → on-demand EPT
  │         │     #BP/#DB     → WHP exit   → ExceptionHandler
  │         └── Game runs natively inside VCPU (VMX non-root)
  │
  └── Host ntdll (real kernel):
        ├── Forwarded syscalls → host ntdll function → real kernel
        └── Result returned to guest via VCPU registers
```

### Ghost Sandbox (EPT Process Migration)

The Ghost Sandbox enables transparent VCPU execution by migrating the target process into a WHP VCPU with identity-mapped guest page tables:

1. **Launcher**: `CreateProcess(SUSPENDED)` → inject `engine.dll` → call `Engine_Init()`
2. **Engine_Init**: enumerate all committed pages of the target process, build 4-level x64 page tables (PML4→PDPT→PD→PT) where every GPA equals its VA, EPT-map every page via `WHvMapGpaRange`, create WHP partition + VCPU #0
3. **Entry Interception**: read PE header `AddressOfEntryPoint`, write a 12-byte trampoline (`mov rax, Engine_VcpuEntry; jmp rax`) at the original entry point, `ResumeThread()`
4. **Bootstrap**: game thread hits trampoline → `RtlCaptureContext` → `BootstrapFromContext(0, ctx, pageTable)` sets CR3 = PML4 GPA, LSTAR → HLT page, ring-3 segment registers (CS=0x33, SS=0x2B), enters `WHvRunVirtualProcessor` loop
5. **VCPU Execution**: game runs at native speed in VMX non-root mode. CPUID, RDTSC, MSR, HLT (syscall), memory faults, and exceptions cause VM exits that the engine handles
6. **Dynamic Page Mapping**: on first access to dynamically allocated pages, the EPT violation handler calls `MapDynamicPage` for on-demand `WHvMapGpaRange`

### Syscall Interception

Two complementary mechanisms:

**Mechanism A: LSTAR→HLT (WHP)**
- The LSTAR MSR is redirected to a page containing only `HLT` instructions
- When the guest executes `SYSCALL`, RIP jumps to the HLT page, the CPU halts, causing a WHP VM exit with `WHvRunVpExitReasonX64Halt`
- `HandleSyscallExit()` dispatches based on RAX (syscall number):
  1. Thread syscalls (`NtCreateThread/Ex`, `NtTerminateThread`) → VCPU migration handlers (gated)
  2. Known spoofed syscalls (`NtQuerySystemInformation`, `NtQueryInformationProcess`) → spoofed results
  3. All others → `ForwardSyscall()` → real host ntdll function → result written back to guest registers

**Mechanism B: INT3 patching (VEH, SystemSpoofer)**
- When WHP is unavailable or for instructions that don't cause VM exits, the engine patches `SYSCALL` (`0F 05`) to `INT3` (`CC`)
- A Vectored Exception Handler catches the `#BP`, reads RAX, calls `DispatchRawSyscall()`, or restores the original `0F 05` and runs a trampoline

### Syscall Forwarding

`SyscallDispatch::BuildForwardTable()` scans **all** ntdll PE exports at runtime, extracts syscall numbers by pattern-matching the `mov eax, SSN` opcode (`0xB8`) in each function stub, and builds an `unordered_map<uint32_t, ForwardEntry>` with function pointer + argument count. ~90 common syscalls have explicit arg counts from a hardcoded table; unknown syscalls default to 4 args. The C++ switch dispatch (0-12 args) correctly passes register-based args (R10, RDX, R8, R9) and stack-based args (args 5+) from the guest context.

**This is build-independent** — syscall numbers are read from the running system's ntdll, so the same engine binary works across Windows versions (Win10 22H2, Win11 24H2, etc.).

Known spoofed syscalls (`NtQuerySystemInformation`, `NtQueryInformationProcess`, `NtOpenKey`, `NtQueryValueKey`, `NtClose`, `NtCreateFile`, `NtQueryObject`, `NtCreateThread`, `NtCreateThreadEx`, `NtTerminateThread`) are explicitly excluded from the forward table and dispatched to dedicated handlers.

### Multi-VCPU Thread Migration (Phase 6, gated)

The engine supports creating child VCPUs (up to 20, indices 0-19) for guest threads. When a guest thread calls `NtCreateThread` or `NtCreateThreadEx`:

1. `HandleCreateThreadSyscall()` allocates a child VCPU index, creates a WHP VCPU on the partition
2. Allocates a 1 MB child stack and builds a `ThreadContext` with register state
3. Creates a **host thread** via `CreateThread()` that enters `ThreadBootstrapEntry` → its own `WHvRunVirtualProcessor` loop
4. Maps the host thread handle to VCPU index for later lookup

This is gated behind `m_childThreadMigrationEnabled` (default `false`) and requires `cpu_count > 1` in config. Without these, `NtCreateThread/Ex/NtTerminateThread` are forwarded to host ntdll, and child threads run as native host threads outside WHP. `ThreadScheduler` provides round-robin multi-VCPU coordination (started but idle at `cpu_count=1`).

### Anti-Hypervisor Detection

Several measures hide the presence of the WHP hypervisor from the guest:
- **CPUID hypervisor leaf** (0x40000000) returns all zeros — no hypervisor vendor string
- **CPUID hypervisor bit** (ECX[31]) is cleared on all leaves
- **WHP anti-detection result list** is populated even when CPUID spoofing is disabled
- **Per-process PID tracking**: via `MagicCpuid`'s PID registration mechanism, CPUID spoofing only applies to the registered target process; all other processes in the WHP partition get pass-through

---

## Components

| Component | File(s) | Role |
|-----------|---------|------|
| **launcher.exe** | `src/launcher/` | CLI: creates target suspended, injects engine.dll, calls Engine_Init, intercepts entry point, resumes |
| **engine.dll** | `src/engine/` | Core engine — orchestrates WHP partition, GuestPageTable, VcpuManager, IAT/EAT patching, syscall forwarding, all handlers |
| **Partition** | `whp/Partition.cpp/.h` | WHP partition lifecycle: Create, SetupCpuCount, SetupMemory, SetupCpuidResultList, Init, MapGpaRange |
| **GuestPageTable** | `whp/GuestPageTable.cpp/.h` | Builds 4-level identity-mapped page tables (PML4→PDPT→PD→PT) mapping GPA=VA for all committed process pages |
| **VcpuManager** | `whp/VcpuManager.cpp/.h` | VCPU lifecycle (CreateVcpu, Run, Stop), BootstrapFromContext, LSTAR→HLT syscall dispatch, exit handling |
| **SyscallDispatch** | `whp/SyscallDispatch.cpp/.h` | Syscall number detection from ntdll, BuildForwardTable (ntdll export scan), ForwardSyscall (0-12 arg switch), NtQSI/NtQIP spoof handlers |
| **CpuidHandler** | `whp/CpuidHandler.cpp/.h` | CPUID exit handler — all standard/extended leaves, brand string, hypervisor leaf hiding, per-process PID tracking |
| **RdtscHandler** | `whp/RdtscHandler.cpp/.h` | RDTSC/RDTSCP exit handler — monotonic TSC with noise injection and delta masking |
| **MsrHandler** | `whp/MsrHandler.cpp/.h` | MSR read/write exit handler — spoofs IA32_PLATFORM_ID, FEATURE_CONTROL, VMX MSRs, etc. |
| **EptHook** | `whp/EptHook.cpp/.h` | EPT violation handler for kernel memory hooks, InstallKernelMemoryHooks, InstallMsrBitmapHook |
| **KuserHook** | `whp/KuserHook.cpp/.h` | KUSER_SHARED_DATA VEH-based spoofing via shared memory overlay (non-WHP fallback) |
| **KuserSync** | `whp/KuserSync.cpp/.h` | KUSER_SHARED_DATA WHP-based synchronization thread (1ms updates inside VCPU) |
| **MagicCpuid** | `whp/MagicCpuid.cpp/.h` | 15-leaf CPUID handshake protocol (HELLO/ACK, GET/SET_GPA, REGISTER_PID, REGISTER_SYSCALL, ENHANCED_MODE, SET/GET_SHM, QUIT) — gated, default off |
| **Canary** | `whp/Canary.cpp/.h` | Guard-page memory scanner detector with VEH callback; 4KB handshake page for engine-target coordination |
| **AllocTracker** | `whp/AllocTracker.cpp/.h` | Monitors JIT/allocated memory via guard pages + VEH for CPUID interception in decrypted code |
| **TimingCoordinator** | `whp/TimingCoordinator.h` | Cross-handler RDTSC→CPUID→RDTSC pattern detection with 3 jitter strategies (uniform/constant/linear) |
| **SystemSpoofer** | `whp/SystemSpoofer.cpp/.h` | VEH-based interception of SGDT/SIDT/SLDT/STR/XGETBV — gated behind config (default off) |
| **ThreadScheduler** | `whp/ThreadScheduler.cpp/.h` | Round-robin multi-VCPU coordinator for child thread migration (started but idle at cpu_count=1) |
| **ExitDispatcher** | `whp/ExitDispatcher.cpp/.h` | WHP exit reason dispatch routing |
| **ExceptionHandler** | `whp/ExceptionHandler.cpp/.h` | WHP VP exception handling (#BP, #DB) |
| **MinimalKernel** | `kernel/MinimalKernel.cpp/.h` | Unified syscall dispatcher owning all emulator instances |
| **SystemProfile** | `kernel/SystemProfile.cpp/.h` | CPU profile data (i9-10900K / Ryzen 9 5950X), brand string, TSC frequency/offset |
| **KernelBackend** | `kernel/KernelBackend.cpp/.h` | IKernelBackend implementation bridging SystemProfile to handlers |
| **ProcessEmu** | `emu/ProcessEmu.cpp/.h` | Spoofs process-related syscalls, PEB, virtual process list |
| **MemoryEmu** | `emu/MemoryEmu.cpp/.h` | Memory-related syscall emulation |
| **FileEmu** | `emu/FileEmu.cpp/.h` | File system spoofing (volume serial, drive info) |
| **RegistryEmu** | `emu/RegistryEmu.cpp/.h` | Registry spoofing (hardware, processor name) |
| **TimingEmu** | `emu/TimingEmu.cpp/.h` | Timing-related syscall spoofing |
| **CryptoEmu** | `emu/CryptoEmu.cpp/.h` | Crypto-related syscall spoofing |
| **ThreadManager** | `emu/ThreadManager.cpp/.h` | Thread lifecycle spoofing |
| **SectionEmu** | `emu/SectionEmu.cpp/.h` | Section object spoofing |
| **ObjectEmu** | `emu/ObjectEmu.cpp/.h` | Object handle spoofing |
| **VirtualState** | `emu/VirtualState.cpp/.h` | Virtual state management |
| **PeLoader** | `emu/PeLoader.cpp/.h` | PE loading emulation |
| **IatPatch** | `proxy/IatPatch.cpp/.h` | IAT and EAT patching (PatchIAT, PatchEAT, RestoreAll) |
| **InlineHook** | `proxy/InlineHook.cpp/.h` | 12-byte `mov rax,imm64; jmp rax` hooks with instruction decoder for trampolines |
| **GpuBridge** | `proxy/GpuBridge.cpp/.h` | GPU DLL passthrough — GPU-intensive calls always go to real system |
| **ModuleCloak** | `proxy/ModuleCloak.cpp/.h` | Module hiding from PEB/LDR |
| **SyscallBridge** | `proxy/SyscallBridge.cpp/.h` | Syscall forwarding bridge |
| **CaptureLogger** | `capture/CaptureLogger.cpp/.h` | Structured tab-separated capture log (100MB auto-rotate) for all fingerprint queries |
| **GpuProfile** | `profile/GpuProfile.cpp/.h` | GPU identity profile for WMI spoofing |
| **StorageProfile** | `profile/StorageProfile.cpp/.h` | Storage device profile (model, serial, size) |
| **HwDetect** | `util/HwDetect.h` | TSC frequency detection (libkrun-derived), CPU vendor/feature detection, feature masking |
| **Proxy DLLs** (13) | `proxydlls/*/` | IAT/EAT interceptors with clean system DLL names (`kernel32.dll`, `ntdll.dll`, `advapi32.dll`, etc.) |
| **verify.exe** | `src/verify/` | 9-phase spoof verification test suite (CPUID, RDTSC, MSR, KUSER, syscalls, PEB, registry, WMI, network) |

---

## Fingerprint Vectors Covered

| Vector | Interception Method | Status |
|--------|-------------------|--------|
| CPUID leaves (0x0-0x40000000) | WHP exit handler (VCPU) | Done |
| CPUID extended leaves (0x80000000+) | WHP exit handler (VCPU) | Done |
| CPUID brand string (0x80000002-4) | CpuidHandler + config-driven brand string | Done |
| CPUID from JIT/allocated memory | AllocTracker guard-page VEH | Done |
| Hypervisor leaf (0x40000000) | CpuidHandler — zeroed (anti-detection) | Done |
| Hypervisor bit (CPUID ECX[31]) | CpuidHandler — cleared on all leaves | Done |
| RDTSC / RDTSCP | WHP exit handler (VCPU) | Done |
| RDTSC→CPUID→RDTSC timing patterns | TimingCoordinator cross-handler detection | Done |
| MSRs (IA32_PLATFORM_ID, FEATURE_CONTROL, etc.) | WHP MsrHandler (VCPU) | Done |
| KUSER_SHARED_DATA (0x7FFE0000) | EPT hook (WHP) + shared memory (VEH fallback) | Done |
| Processor brand string | Registry + CPUID brand leaves | Done |
| ACPI MADT (processor count) | Syscall intercept NtQuerySystemInformation | Done |
| SMBIOS / DMI | Syscall intercept | Done |
| WMI (Win32_Processor, Win32_VideoController) | wbem_proxy COM wrapper | Done |
| NtQuerySystemInformation | LSTAR→HLT → SyscallDispatch (spoofed) | Done |
| NtQueryInformationProcess | LSTAR→HLT → SyscallDispatch (spoofed) | Done |
| Registry (hardware, processor name) | advapi32_proxy + ntdll_proxy | Done |
| Volume serial / drive info | kernel32 proxy | Done |
| Timing analysis | TimingEmu + MinimalKernel | Done |
| PEB / TEB offsets | ProcessEmu via MinimalKernel | Done |
| PEB BeingDebugged / NtGlobalFlag | Inline write in engine init | Done |
| Network adapter info | iphlpapi_proxy | Done |
| DNS queries | dnsapi_proxy | Done |
| Crypto provider info (container name) | crypt32_proxy | Done |
| Session / terminal info | wtsapi32_proxy | Done |
| Security context | secur32_proxy | Done |
| HTTP connections | winhttp_proxy | Done |
| Memory scanner detection | Canary guard-page + VEH callback | Done |
| Target registration / handshake | MagicCpuid (15-leaf handshake, gated) | Done |
| SGDT / SIDT / SLDT / STR | SystemSpoofer VEH (gated, default off) | Done |
| XGETBV (XSAVE feature bits) | SystemSpoofer VEH (gated, default off) | Done |
| RDMSR (ring-3 accessible) | SystemSpoofer VEH | Done |
| GetProcAddress dynamic lookups | RegisterProxyFunctions + Proxy_GetProcAddress hook | Done |
| NtCreateThread/NtCreateThreadEx | LSTAR→HLT → HandleCreateThreadSyscall (VCPU migration, gated) | Done |
| NtTerminateThread | LSTAR→HLT → HandleTerminateThreadSyscall (child VCPU teardown) | Done |
| All syscalls (forwarded) | LSTAR→HLT → ForwardSyscall → host ntdll → real kernel | Done |
| All queries captured to disk | CaptureLogger | Done |

---

## Configuration

Default: `config/config.ini` (relative to launcher binary). Config profiles specify per-leaf CPUID values, MSR values, GPU profile (Intel HD 4400 / NVIDIA GeForce 840M), storage/network/hardware info, and feature toggles.

### Feature Toggles

```ini
[system_spoofer]     enabled = false     ; VEH for SGDT/SIDT/SLDT/STR/XGETBV (off for Denuvo)
[eat]                enabled = false     ; Export Address Table patching
[forwarding]         enabled = true      ; Syscall forwarding (Ghost Sandbox)
[cpuid]              status = 0          ; CPUID spoofing (0=disabled)
[rdtsc]              status = 0          ; RDTSC spoofing
[msr]                status = 1          ; MSR spoofing
[kuser]              status = 1          ; KUSER_SHARED_DATA spoofing
[process]            status = 1          ; Process info spoofing
[registry]           status = 1          ; Registry spoofing
[file]               status = 1          ; File spoofing
[timing]             status = 1          ; Timing spoofing
[magic]              status = 0          ; MagicCpuid handshake (off by default)
```

### Capture Mode

To log all fingerprint queries without spoofing (for analysis/profile creation):

```bat
copy config\capture.ini config\config.ini
launcher.exe --target C:\Path\to\target.exe
```

`CaptureLogger` records all intercepted queries (CPUID, MSR, RDTSC, syscalls) to a structured TSV log file with 100MB auto-rotation.

---

## Build

### Prerequisites

- Windows 10/11 x64 with Visual Studio 2022 C++ workload
- CMake 3.20+
- Windows SDK (includes `WinHvPlatform.h` / `WinHvPlatform.lib`)
- Optional: Hyper-V + Windows Hypervisor Platform enabled

### Presets

| Preset | Arch | Config | Compiler | WHP Support |
|--------|------|--------|----------|-------------|
| `msvc-x64` | x64 | Release | MSVC | Yes |
| `msvc-x64-debug` | x64 | Debug | MSVC | Yes (verbose logging) |
| `msvc-x86` | x86 | Release | MSVC | Limited |
| `msvc-x86-debug` | x86 | Debug | MSVC | Limited |
| `mingw-x64` | x64 | Release | MinGW | No |
| `mingw-x86` | x86 | Release | MinGW | No |

### Build Commands

```bat
:: x64 Release (default)
cmake --preset msvc-x64
cmake --build --preset msvc-x64

:: x64 Debug with verbose logging
cmake --preset msvc-x64-debug
cmake --build --preset msvc-x64-debug
```

### Build Helper

`scripts\build.bat` accepts flags: `debug`, `x86`, `x86-debug`, `mingw`, `mingw-x64`.

### Output

All binaries go to `build/<preset>/bin/Release` (or `Debug`):

```
engine.dll            Core engine (WHP, GuestPageTable, VcpuManager, SyscallDispatch, proxy, handlers)
launcher.exe          Process launcher + injector + entry point interceptor
verify.exe            9-phase spoof verification test suite
handshake_test.exe    Magic CPUID handshake verification tool
capture_tool.exe      Standalone fingerprint capture tool
msr_reader.exe        MSR register reader (requires semav6msr64 kernel driver)
kernel32.dll          Proxy DLL (clean system DLL name)
ntdll.dll             Proxy DLL (clean system DLL name)
kernelbase.dll        Proxy DLL (clean system DLL name)
advapi32.dll          Proxy DLL (clean system DLL name)
user32.dll            Proxy DLL (clean system DLL name)
wbem.dll              Proxy DLL (clean system DLL name)
wtsapi32.dll          Proxy DLL (clean system DLL name)
secur32.dll           Proxy DLL (clean system DLL name)
crypt32.dll           Proxy DLL (clean system DLL name)
winhttp.dll           Proxy DLL (clean system DLL name)
dnsapi.dll            Proxy DLL (clean system DLL name)
iphlpapi.dll          Proxy DLL (clean system DLL name)
ws2_32.dll            Proxy DLL (clean system DLL name)
```

---

## Verification Tools

| Tool | Description |
|------|-------------|
| **verify.exe** | 9-phase test suite: CPUID, RDTSC, MSR, KUSER, syscalls, PEB, registry, WMI, network — all spoofed values vs expected |
| **handshake_test.exe** | Verifies the Magic CPUID 15-leaf handshake protocol (HELLO/ACK, GPA exchange, PID registration, etc.) |
| **capture_tool.exe** | Standalone capture tool — logs all fingerprint queries for 5 minutes without spoofing, output as TSV |
| **msr_reader.exe** | Reads MSR registers via the `semav6msr64` kernel driver IOCTL protocol |
| **test_sections.ps1** | PowerShell bisect test script — tests each spoofing section in isolation against a target game, automates config generation and log analysis |

---

## Performance

| Mode | Execution overhead | Mechanism |
|------|-------------------|-----------|
| **WHP VCPU** (VMX non-root) | **~0%** (~50-200 exits × ~2000 cycles each) | Only CPUID/RDTSC/MSR/HALT cause VM exits; all other instructions run natively |
| **Syscall Forwarding** | Per-syscall: ~2000 cycle exit + function call overhead | Every guest SYSCALL exits via LSTAR→HLT, dispatched to host ntdll |
| **SystemSpoofer VEH** (host) | **5-30%+** per patched instruction | Each SGDT/SIDT/SLDT/STR/XGETBV triggers kernel exception (5000-10000+ cycles) |
| **EPT page fault** | ~5000 cycles on first access | On-demand WHvMapGpaRange for dynamically allocated pages |

### Why WHP has near-zero overhead

WHP uses Intel VT-x hardware virtualization. When `WHvRunVp` is called, the CPU enters VMX non-root mode and executes the guest code **natively** — `mov`, `add`, `cmp`, SSE/AVX, and most syscall instructions run at full speed with zero interpretation. Only CPUID, RDTSC, MSR access, and HLT cause VM exits (~1000-3000 cycles each). During normal execution, zero exits occur.

---

## Limitations

- **WHP `WHvCreatePartition` requires Hyper-V Platform enabled** — otherwise returns `0xC0351000`
- **KUSER_SHARED_DATA at `0x7FFE0000`** works via EPT (WHP) only; VEH fallback available but less transparent
- **IAT/EAT patching** applies to modules loaded after engine init; pre-loaded system DLLs use proxy DLL shims
- **GPU-intensive workloads** pass through via GpuBridge (always fall through to real GPU)
- **SystemSpoofer VEH** uses INT3 patches for SGDT/SIDT/SLDT/STR/XGETBV — may be detected by anti-tamper (gated behind config, off by default for Denuvo)
- **Forward table arg counts** — unknown syscalls default to 4 args; if a >4-arg syscall is missing from the table, the forwarded call will read garbage from the stack
- **Context capture via RtlCaptureContext** captures at Engine_VcpuEntry, not at the original game entry point. RSP is inside Engine_VcpuEntry's frame, not the loader's initial stack. For modern MSVC CRT startups using PEB-based init this works; if issues arise, an assembly register-save stub is needed
- **Denuvo persistent blacklist** — after WHP is detected once, Denuvo persists state across launches. Cleanup functions delete cache files in `game_dir`, `%appdata%\Denuvo\`, and `%TEMP%\dns*`
- **Proxy DLLs use clean system names** loaded with absolute paths via `LoadLibraryW`; GetProcAddress hook uses engine-registered function table
- **WHP-only host machines** — game must have WHP available. No fallback to pure emulation
- **Single VCPU by default** — child thread VCPU migration (Phase 6) is code-complete but gated behind `cpu_count > 1` in config and `SetChildThreadMigrationEnabled(true)`. Without these, child threads run as native host threads outside WHP
- **Syscall number stability** — SSNs vary across Windows builds; dynamic detection from ntdll handles this, but any run-time resolution failure causes the engine to fall back to forwarding

---

## Documentation

| Document | Contents |
|----------|----------|
| `docs/ARCHITECTURE.md` | Problem statement, architecture overview, comparison table (custom hypervisors vs Symbiote), detection surface analysis |
| `docs/TECHNIQUES.md` | Per-vector deep dives: CPUID, RDTSC, MSR, KUSER, syscalls, registry, WMI, PEB/TEB, proxy DLLs, MagicCpuid handshake, memory scanner canary — with degradation modes comparison |
| `docs/RESULTS.md` | Real i7-4510U vs spoofed i9-10900K comparison across 20 fingerprint vectors with detailed tables |
| `docs/RESEARCH.md` | 7 research areas: WHP virtualization, VEH fallback, IAT patching, inline hooks, MSR shadowing, anti-detection defensive research (13 vectors with mitigations), future directions |

---

## License

This project is open source for fair usage and educational study.

The concept and implementation are the original work of the author. All contributors are recognized as rightful co-owners of their contributions, with equal standing to the original author. The project exists for research purposes only.

See `LICENSE` for full terms.
