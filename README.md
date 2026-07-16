# Symbiote

**Ring-3 Windows userspace hardware fingerprint spoofing framework — educational / security research**

Symbiote is a research platform for studying hardware fingerprinting techniques — intercepting and spoofing CPUID, MSR, KUSER_SHARED_DATA, WMI, registry, syscalls, and timing entirely from user mode **without kernel drivers**. It uses Microsoft's **Windows Hypervisor Platform (WHP)** as its execution backend, with **EPT process migration (Ghost Sandbox)** for transparent guest execution inside a Hyper-V VCPU, **LSTAR→HLT syscall interception with host ntdll forwarding**, **proxy DLLs with IAT/EAT patching**, **config-gated VEH handlers**, **BEL (Big Emulator Lock) multi-VCPU architecture**, **EPT-based execution hook single-step system**, **Steam sandbox launcher**, **GPU DXVK passthrough**, and **WHP state snapshot/restore**.

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
    ├── launcher/                 # launcher.exe — CLI arg parsing, Steam sandbox detection,
    │                             #   suspended process creation, engine.dll injection,
    │                             #   Engine_Init, entry point interception
    ├── engine/                   # engine.dll — core engine (40+ WHP files, 24 emu, 17 proxy, ...)
    │   ├── whp/                  # WHP partition, GuestPageTable, VcpuManager, SyscallDispatch,
    │   │                         #   CpuidHandler, RdtscHandler, MsrHandler, EptHook, KuserHook,
    │   │                         #   KuserSync, MagicCpuid, Canary, AllocTracker,
    │   │                         #   TimingCoordinator, SystemSpoofer, ThreadScheduler,
    │   │                         #   ExitDispatcher, ExceptionHandler, EptExecHook,
    │   │                         #   KernelLock (BEL), Snapshot,
    │   │                         #   WatchdogTracker, EptSplitView, AcpiTimerHandler
    │   ├── kernel/               # MinimalKernel (unified syscall dispatcher),
    │   │                         #   SystemProfile (CPU profiles), KernelBackend (bridge)
    │   ├── emu/                  # Syscall emulators: ProcessEmu, MemoryEmu, FileEmu, RegistryEmu,
    │   │                         #   TimingEmu, CryptoEmu, ThreadManager, SectionEmu, ObjectEmu,
    │   │                         #   VirtualState, PeLoader, DeviceIoEmu, ThreadHider
    │   ├── proxy/                # IatPatch (IAT/EAT patching, restore), InlineHook (12-byte jmp),
    │   │                         #   GpuBridge (GPU DLL passthrough), DxvkIntegration (DXVK proxy bypass),
    │   │                         #   ModuleCloak (PEB hiding), SyscallBridge
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

Known spoofed syscalls (`NtQuerySystemInformation`, `NtQueryInformationProcess`, `NtOpenKey`, `NtOpenKeyEx`, `NtQueryValueKey`, `NtClose`, `NtCreateFile`, `NtQueryObject`, `NtCreateThread`, `NtCreateThreadEx`, `NtTerminateThread`) are explicitly excluded from the forward table and dispatched to dedicated handlers. NtOpenKey/Ex are intercepted to block registry queries to hypervisor-related service keys (`\registry\machine\system\currentcontrolset\services\hypervisor`, `hvservice`, `VMBus`, etc.), returning `STATUS_OBJECT_NAME_NOT_FOUND`.

### Big Emulator Lock (BEL) — Multi-VCPU Architecture

The engine implements the **Big Emulator Lock** pattern: all VCPU threads acquire a shared `KernelLock` before entering C++ handler code and release it during guest execution (`WHvRunVirtualProcessor`). This serializes all emulator state access while allowing parallel guest execution across VCPUs.

**Per-VCPU GDT**: each VCPU (indices 0-19) receives a unique GDT at `PER_VCPU_GDT_BASE + n * 0x1000` with 6-entry x64 descriptors (null, ring-0 code/data, ring-3 code/data, ring-3 long-mode code). This prevents WOW64 threads on different VCPUs from leaking TEB bases through shared FS-segment selectors.

**ThreadScheduler**: provides a round-robin ready queue (`MarkReady`/`PickNextVcpu`) for fair time-slicing across VCPUs, with a scheduler loop thread and `SyncBarrier`/`ExitCoordinator` for coordinated start/stop.

**Multi-VCPU Thread Migration** (Phase 6, gated): when a guest thread calls `NtCreateThread` or `NtCreateThreadEx`:
1. `HandleCreateThreadSyscall()` allocates a child VCPU index, creates a WHP VCPU on the partition
2. Allocates a 1 MB child stack and builds a `ThreadContext` with register state
3. Creates a **host thread** via `CreateThread()` that enters its own `WHvRunVirtualProcessor` loop (BEL-synchronized)
4. Maps the host thread handle to VCPU index for later lookup

This is gated behind `m_childThreadMigrationEnabled` (default `false`) and requires `cpu_count > 1` in config.

### Anti-Hypervisor Detection

Several measures hide the presence of the WHP hypervisor from the guest. These are organized into **4 phases** targeting Denuvo anti-tamper detection vectors:

**Phase 1 — Syscall / MSR / Register:**
- **CPUID hypervisor leaf** (0x40000000) returns all zeros — no hypervisor vendor string
- **CPUID hypervisor bit** (ECX[31]) is cleared on all leaves
- **WHP anti-detection result list** is populated even when CPUID spoofing is disabled
- **Per-process PID tracking**: via `MagicCpuid`'s PID registration mechanism, CPUID spoofing only applies to the registered target process; all other processes in the WHP partition get pass-through
- **NtQuerySystemInformation info class 0x5B** (SystemHypervisorInformation) returns 16 zero bytes
- **NtQuerySystemInformation info class 0x9F** (SystemHypervisorDetailInformation) returns 0x70 zero bytes
- **RDMSR(LSTAR)** spoofed to return real KiSystemCall64 address (resolved via ntoskrnl export walk), not 0
- **CR4 register** VMXE (bit 13) and SMXE (bit 14) masked — hypervisor-related bits hidden from guest reads

**Phase 2 — Timing / VEH:**
- **RDTSC/RDTSCP VM-exit cost compensation**: when `TimingCoordinator::DetectRdtscAfterCpuid` detects a CPUID→RDTSC pattern, the TSC is adjusted by subtracting ~2000 cycles (VM-exit overhead), returning `lastPreExitTsc + 80` to mimic bare-metal CPUID timing
- **SystemSpoofer VEH stack spoiling defense**: VEH handler saves the top 64 QWORDs (512 bytes) of thread stack on entry and restores them before `CONTINUE_EXECUTION`, defeating Denuvo's stack-integrity checks after exception dispatch

**Phase 3 — WMI / Registry:**
- **Win32_ComputerSystem WMI spoofing**: `HypervisorPresent=false`, realistic Model/SystemType/Manufacturer (i9-10900K desktop profile). WMI class type is tracked per-object (`WMI_CLASS_PROCESSOR` vs `WMI_CLASS_COMPUTER_SYSTEM`) to disambiguate shared property names like `Manufacturer`
- **Registry path filtering**: `NtOpenKey`/`NtOpenKeyEx` intercepted inside `DispatchRawSyscall` — guest OBJECT_ATTRIBUTES parsed to extract the registry key path. Paths containing `hypervisor`, `hvservice`, `VMBus`, `Hyper-V`, or `HypervisorPresent` return `STATUS_OBJECT_NAME_NOT_FOUND` (0xC0000034)

**Phase 4 — Config gating + EPT execution hooks:**
- All aggressive anti-detection features (AllocTracker ntdll inline hooks, SystemSpoofer VEH) gated behind `[hypervisor_hiding]` config section with defaults `alloc_tracker = false, system_spoofer = false`. This prevents detectable features from being active when not explicitly needed
- **EptExecHook** supersedes AllocTracker when WHP is available — strips EXEC from EPT entries for targeted pages and uses WHP #DB single-step instead of VEH guard pages. Undetectable by user-mode anti-tamper since EPT is invisible from ring-3. When EptExecHook is active, AllocTracker init is skipped with a warning
- **Expanded exception bitmap**: `#UD` (invalid opcode), `#PF` (page fault), `#MF` (x87 FP error), `#XM` (SIMD FP error) are now handled in the VCPU exit loop. `#UD` skips 1 byte; `#PF` calls `MapDynamicPage` as EPT violation fallback; `#MF`/`#XM` clear and continue
- **EPT map coalescing**: contiguous GPA ranges in deferred map/unmap queues are merged into single `WHvMapGpaRange`/`WHvUnmapGpaRange` calls, avoiding ~second-long stalls from page-by-page EPT updates

**Phase 4b — Denuvo state cleanup at exit:**
- `CleanupDenuvoState()` removes Denuvo cache files from `game_dir`, `%appdata%\Denuvo\`, and `%TEMP%\dns*` before engine shutdown, preventing persistent blacklist state from surviving across launches

**Phase 5 — VEH stack-fault hardening:**
- All VEH handlers (SystemSpoofer, AllocTracker, Canary) now implement the **64-QWORD stack save/restore** pattern to defeat Denuvo's stack-spoiling detection. Previously only SystemSpoofer had this defense

**Phase 6 — Steam sandbox + DXVK passthrough:**
- **SteamGameDetector**: VDF text parser for `libraryfolders.vdf` and `appmanifest_*.acf`, enumerates all Steam library folders and installed games, scores executables by name-token match / depth / size to find the main game binary
- **`launcher.exe --steam-launch "Game Name"`**: auto-detects Steam game, resolves best executable via scorer, sets `SteamAppId` env var, launches under WHP
- **DxvkIntegration**: detects DXVK DLLs (d3d9, d3d10, d3d10_1, d3d10core, d3d11, dxgi) alongside target exe, pre-loads them to initialize before the game hooks, sets `g_dxvkBypassActive` flag so proxy interception skips DXVK modules
**Phase 7 — Snapshot/restore:**

- Full WHP state serialization: all 36 VCPU registers (GPRs, CRs, DRs, segments, EFER, STAR/LSTAR/CSTAR, GDTR/IDTR/TR/LDTR), memory region metadata (GPA, size, flags via Partition tracking), and EptExecHook hook list
- `Snapshot::Create()` captures state to binary buffer; `WriteToFile()` saves as `.snap`; `LoadFromFile()` validates magic/version; `Restore()` re-sets VCPU registers and re-registers EPT hooks
- Format: magic `SYMBIOTE` + version 1 + QPC timestamp + VCPU register blocks + memory region blocks + handler data

**Phase 8 — Enhanced Anti-Detection (KUSER fields, watchdog, β-time, EPT split-view):**

- **KUSER_SHARED_DATA field expansion**: `ApplyStaticSpoofs()` now writes all DRM-read fields — NtMajorVersion (0x260), NtMinorVersion (0x261), BuildNumber (0x262-0x263), NativeProcessorArchitecture (0x26A-0x26B), ProductTypeIsValid (0x268), SuiteMask (0x26C), NumberOfPhysicalPages (0x2D8), ProcessorFeatures (0x270-0x2CF, five 64-bit feature bitmaps), ActiveProcessorCount (0x3C0). All fields loaded from config or default to Win10 Pro values matching the spoof profile
- **Leaf-specific CPUID timing costs**: `RdtscHandler::CplLeafCost()` returns per-leaf bare-metal TSC cycle counts (80-600 cycles depending on leaf complexity) — used to calculate VM-exit cost compensation more precisely than the previous single 80-cycle constant
- **RDTSCP VCPU-aware RCX**: `HandleRdtscp()` sets RCX to the actual VCPU index (`m_vpIndex`) instead of hardcoded 1 — prevents topology-based timing fingerprints
- **WatchdogTracker** (`WatchdogTracker.h/.cpp`): detects Denuvo threaded integrity watchdogs by intercepting `NtCreateThreadEx` in `OnThreadCreate()`, checks if the start RIP is from non-image memory (Denuvo JIT/decrypted pages), registers EPT exec hooks on watchdog GPA pages via `EptExecHook::RegisterPageHook()`. The static callback `OnWatchdogExec()` fires on each execution hit. `SimulateIntegrityCheck()` re-registers hooks to simulate periodic verification. Hooked pages are saved/restored across snapshot boundaries
- **β-time clock correlation**: `TimingCoordinator` upgraded from struct to class with `SnapshotBaseClocks()` and `GetConsistent*()` methods (GetConsistentQpc, GetConsistentTsc, GetConsistentSysTime, GetConsistentTickCount, GetConsistentTimeGetTime) — all time sources reference a shared base snapshot, ensuring correlated drifts that match bare-metal clock behavior. `NtQuerySystemTime` handler returns consistent values derived from the same base
- **WMI surface expansion**: `wbem_proxy` now spoofs `Win32_BaseBoard` (Manufacturer, Product, Version, SerialNumber), `Win32_BIOS` (SMBIOSBIOSVersion, ReleaseDate, SerialNumber), `Win32_DiskDrive` (Model, SerialNumber, InterfaceType, MediaType, Size, BytesPerSector, Partitions). `Win32_ComputerSystem` expanded with Domain, PrimaryOwnerName, TotalPhysicalMemory, NumberOfProcessors
- **NtQueryVirtualMemory PE header spoofing**: `SyscallDispatch::HandleNtQueryVirtualMemory()` intercepts `MemoryBasicInformation` queries for ntdll/.engine pages — forwards to real NtQueryVirtualMemory, then overwrites the output: ensures .text pages show as clean `PAGE_EXECUTE_READ` with `PAGE_GUARD/NOCACHE/WRITECOMBINE` cleared and `Type = MEM_IMAGE`. Defeats Denuvo's PE header integrity verification that detects EAT/IAT patches
- **EAT patching enabled**: `[eat] enabled = true` in config activates `IatPatch::PatchEAT()` — patches the Export Address Table of all loaded DLLs to route exports through proxy DLLs. Previously disabled by default due to detection risk; combined with NtQueryVirtualMemory spoofing, PE header reads now show clean exports
- **EPT split-view (process cloaking)**: `EptSplitView` (`EptSplitView.h/.cpp`) implements per-VCPU memory view switching — registers GPA ranges with visible/hidden host VAs. `RegisterHiddenRange()` stores page metadata; `SetPageVisibility()` records per-VCPU overrides; `ApplyViewForVcpu()` unmaps and remaps GPA ranges to the appropriate VA based on the target VCPU. Used to hide engine DLL pages from child process VCPU instances while keeping them visible to the parent VCPU. Works by swapping `WHvMapGpaRange` mappings atomically before resuming the target VCPU
- **SMBIOS/DMI table masking**: `HandleNtQuerySystemInformation()` now intercepts info class `0x1D` (SystemFirmwareTableInformation / 29) — returns `STATUS_INFO_LENGTH_MISMATCH` with zero return length, preventing DRM from reading real SMBIOS tables that would leak the host hardware identity

**Phase 9 — Comprehensive Anti-Detection (512-leaf CPUID, CounterUpdater, ACPI/HPET, IOCTL Hook, WMI/SMBIOS/Registry expansion, Thread Hider, EPT perf):**

- **512-leaf CPUID pre-population**: `GetComprehensiveCpuidResultList()` enumerates all standard leaves (0x00-0xFF), extended leaves (0x80000000-0x800000FF), and hypervisor leaves (0x40000000-0x400000FF) via `__cpuidex`, applies feature masking, and loads ALL leaves into the WHP result list via `WHvSetPartitionProperty(WHvPartitionPropertyCodeCpuidResultList)`. **This eliminates VM-exits for unlisted leaves** — Denuvo's RDTSC→CPUID→RDTSC timing delta is measured on exits, and since no exits occur for any standard leaf, the timing vector is neutralized
- **CounterUpdater synthetic TSC thread**: Background thread (`RdtscHandler::CounterUpdaterThread`) advances a synthetic TSC at configured frequency (~3GHz) at ~100us intervals. RDTSC/RDTSCP handlers use `s_counterTsc` instead of real TSC + offset. Since the synthetic counter runs continuously and independently of VM-exit events, TSC deltas across CPUID calls show bare-metal timing — no VM-exit overhead visible
- **Realistic CPU noise model**: `AddRealisticNoise()` with per-vendor profiles (Intel: mean=40, amp=20, min=60; AMD: mean=80, amp=40, min=120) and rare ~0.2ms cache-miss spikes
- **Expanded CplLeafCost**: from 11 leaves to 26+ leaves covering all common CPUID leaves with measured bare-metal cycle costs
- **NtDeviceIoControlFile hook**: `DeviceIoEmu` installs a 12-byte inline hook on `ntdll!NtDeviceIoControlFile` to intercept WHP IOCTL calls. `IOCTL_WHV_GET_PARTITION_PROPERTY` is intercepted for `ProcessorCount` (returns spoofed count). All WHP IOCTLs are logged for analysis
- **ACPI PM Timer / HPET synthetic timers**: `AcpiTimerHandler` generates synthetic ACPI PM timer (port 0x608, 3.579545 MHz, 24-bit) and HPET counter (0xFED00000 + offset, ~10MHz). These alternative clock sources are cross-referenced with the spoofed TSC to maintain consistency — prevents Denuvo from reading raw hardware timers as a TSC bypass
- **Expanded WMI (10+ new classes)**: `wbem_proxy` now spoofs `Win32_VideoController` (NVIDIA RTX 3080 identity), `Win32_NetworkAdapter` (Intel I225-V, Dell OUI MAC), `Win32_PhysicalMemory` (Kingston DDR4-2666 16GB), `Win32_USBController` (Intel xHCI), `CIM_Sensor`, `Win32_TemperatureProbe` (45C reading), `Win32_Fan`, `Win32_VoltageProbe` (1.2V). Sensors return realistic values instead of empty — prevents VM detection via missing hardware sensors
- **Expanded SMBIOS (10 types → 17 types)**: Added Type 7 (L1/L2/L3 cache with proper sizes matching CPU profile), Type 17 (DDR4-2666 16GB SODIMM memory devices), Type 19 (memory array mapping), Type 21 (PS/2 trackpoint), Type 22 (Li-Ion 66WH battery), Type 11 (OEM strings), Type 13 (BIOS language). Buffer expanded from 0x800 to 0x1000 bytes
- **Hyper-V registry artifact blocking**: `RegistryEmu::IsSensitiveKey()` expanded from 5 patterns to 18 patterns — blocks `hyper-v`, `hyperv`, `vmbus`, `vmics`, `vmide`, `vms3`, `msvm`, `vmwp`, `vmgencounter`, `qemu`, `virtual`, `HARDWARE\DESCRIPTION\System\BIOS`, `HARDWARE\DEVICEMAP\Scsi`, `Services\VMBus`, `Services\HyperV`
- **Thread Hider**: `ThreadHider` registers engine threads for filtering from `CreateToolhelp32Snapshot`/`Thread32First`/`Thread32Next` enumeration. Integrated with `NtQuerySystemInformation(SystemProcessInformation)` handler to filter hidden threads from process lists
- **EPT split-view optimizations**: View generation tracking skips redundant `WHvMapGpaRange`/`WHvUnmapGpaRange` calls when view hasn't changed. 2MB large page support for contiguous regions (`GetOptimalPageSize()`). `ReadHiddenMemory()`/`WriteHiddenMemory()` direct access without view switching. `ProtectMemoryRange()` for RX-only EPT mapping (blocks Denuvo write-verify integrity checks)
- **INT3 anti-memory-scanning camouflage**: `SystemSpoofer::ApplyCamouflage()` replaces INT3 (0xCC) breakpoints with multi-byte NOP instructions (66 90, 0F 1F 00, etc.) when patches are not actively triggered. `RestorePatches()` re-applies INT3 before execution. Prevents Denuvo memory CRC scans from detecting VEH patches
- **Enhanced TimingCoordinator**: `JITTER_REALISTIC` strategy replaces `JITTER_UNIFORM` as default. `CpuJitterProfile` struct provides per-CPU-model jitter parameters (i9/i7/i5/Xeon/Ryzen). `GetConsistentAcpiPmTimer()` and `GetConsistentHpetCounter()` provide cross-correlated values. `VerifyClockConsistency()` placeholder for multi-source consistency checks
- **Windows version compatibility**: Syscall numbers read from running ntdll at runtime — same engine binary works across Win10 22H2, Win11 24H2, and future builds

The Rule-5 detection surface (CPUID.1:ECX[31], WHP `WHvGetPartitionProperty` at the Hyper-V L0 level) still requires a nested type-2 hypervisor (modified WinVisor as L1) for full Ring-3 coverage — this is planned for Phase B.

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
| **EptExecHook** | `whp/EptExecHook.cpp/.h` | EPT-based execution hook single-step system — strips EXEC from EPT, catches exec faults, arms #DB single-step, re-strips. Supersedes AllocTracker when WHP available |
| **WatchdogTracker** | `whp/WatchdogTracker.cpp/.h` | Denuvo threaded integrity watchdog detection — intercepts NtCreateThreadEx, registers EPT exec hooks on watchdog pages, periodic `SimulateIntegrityCheck()` |
| **EptSplitView** | `whp/EptSplitView.cpp/.h` | Per-VCPU memory view switching for process cloaking — registers GPA ranges with visible/hidden VAs, `ApplyViewForVcpu()` swaps mappings atomically |
| **KernelLock (BEL)** | `whp/KernelLock.cpp/.h` | CRITICAL_SECTION-based mutex with owner-tracking — serializes C++ handler code, released during guest execution for parallel VCPU execution |
| **Snapshot** | `whp/Snapshot.cpp/.h` | Full WHP state serialization (36 VCPU registers, memory regions, EptExecHook hooks) with file I/O and restore |
| **DxvkIntegration** | `proxy/DxvkIntegration.cpp/.h` | DXVK passthrough — detects DXVK DLLs, pre-loads them, sets bypass flag so proxy hooks skip DXVK modules |
| **SteamGameDetector** | `launcher/SteamGameDetector.cpp/.h` | VDF parser for libraryfolders.vdf + appmanifest.acf, executable scoring heuristic, `--steam-launch` mode |
| **ThreadScheduler** | `whp/ThreadScheduler.cpp/.h` | Round-robin multi-VCPU coordinator with BEL: MarkReady/PickNextVcpu, SyncBarrier, ExitCoordinator |
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
| **TimingCoordinator** | `whp/TimingCoordinator.h/.cpp` | Cross-clock β-time correlation — `SnapshotBaseClocks()`, `GetConsistent*()` methods ensure consistent drift across QPC/TSC/SysTime/TickCount/timeGetTime |
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
| NtQuerySystemInformation (0x5B hypervisor) | LSTAR→HLT → HandleNtQuerySystemInformation → 16 zero bytes | Done |
| NtQuerySystemInformation (0x9F hypervisor detail) | LSTAR→HLT → HandleNtQuerySystemInformation → 0x70 zero bytes | Done |
| RDMSR(LSTAR / 0xC0000082) | MsrHandler → cached KiSystemCall64 from ntoskrnl export | Done |
| CR4 VMXE/SMXE | SetContextRegisters → bits 13/14 masked | Done |
| CPUID→RDTSC timing delta | TimingCoordinator + RdtscHandler → 80-cycle bare-metal cost | Done |
| VEH stack frame integrity | SystemSpoofer → 64-QWORD stack save/restore | Done |
| Win32_ComputerSystem WMI (HypervisorPresent) | wbem_proxy → SpoofedComputerSystem class | Done |
| Registry hypervisor service keys | NtOpenKey path filter → STATUS_OBJECT_NAME_NOT_FOUND | Done |
| AllocTracker inline hooks (config-gated) | hypervisor_hiding.alloc_tracker=false (off by default) | Done |
| KUSER_SHARED_DATA all fields (0x260-0x3C0) | KuserSync ApplyStaticSpoofs — 12 fields from config | Done |
| CPUID→RDTSCP leaf-specific timing | RdtscHandler::CplLeafCost — 80-600 cycle per-leaf costs | Done |
| RDTSCP RCX processor ID per-VCPU | HandleRdtscp sets RCX = m_vpIndex | Done |
| β-time multi-source clock correlation | TimingCoordinator SnapshotBaseClocks + GetConsistent* | Done |
| Denuvo watchdog thread detection | WatchdogTracker OnThreadCreate + EPT exec hook | Done |
| Win32_BaseBoard WMI | wbem_proxy SpoofedBaseBoard class | Done |
| Win32_BIOS WMI | wbem_proxy SpoofedBIOS class | Done |
| Win32_DiskDrive WMI | wbem_proxy SpoofedDiskDrive class | Done |
| NtQueryVirtualMemory PE header spoofing | SyscallDispatch HandleNtQueryVirtualMemory | Done |
| EAT patching | IatPatch::PatchEAT + config [eat] enabled=true | Done |
| EPT split-view (process cloaking) | EptSplitView per-VCPU GPA swap | Done |
| SMBIOS/DMI table masking | SyscallDispatch HandleNtQuerySystemInformation 0x1D | Done |

---

## Configuration

Default: `config/config.ini` (relative to launcher binary). Config profiles specify per-leaf CPUID values, MSR values, GPU profile (Intel HD 4400 / NVIDIA GeForce 840M), storage/network/hardware info, and feature toggles.

### Feature Toggles

```ini
[hypervisor_hiding]  alloc_tracker = false  ; AllocTracker (VEH guard pages — off by default; EptExecHook supersedes)
[hypervisor_hiding]  system_spoofer = false ; SystemSpoofer VEH (SGDT/SIDT/SLDT/STR/XGETBV — off for Denuvo)
[system_spoofer]     enabled = false        ; Legacy fallback (same as hypervisor_hiding.system_spoofer)
[eat]                enabled = true         ; Export Address Table patching (Phase 8)
[watchdog]           enabled = true         ; Denuvo watchdog detection (WatchdogTracker)
[ept_split_view]     enabled = true         ; EPT split-view (process cloaking)
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
[vm]                 cpu_count = 2       ; Virtual CPU count (for multi-VCPU BEL + child thread migration)
```

Note: `hypervisor_hiding.system_spoofer` and `system_spoofer.enabled` both control the same feature. The engine reads `hypervisor_hiding.system_spoofer` first, with `system_spoofer.enabled` as fallback.

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
| **BEL multi-VCPU** | **~0%** (lock is uncontended in practice) | KernelLock released during WHvRunVirtualProcessor; only contended during concurrent VM-exits |
| **Syscall Forwarding** | Per-syscall: ~2000 cycle exit + function call overhead | Every guest SYSCALL exits via LSTAR→HLT, dispatched to host ntdll |
| **SystemSpoofer VEH** (host) | **5-30%+** per patched instruction | Each SGDT/SIDT/SLDT/STR/XGETBV triggers kernel exception (5000-10000+ cycles) |
| **EPT page fault** | ~5000 cycles on first access | On-demand WHvMapGpaRange for dynamically allocated pages |
| **EptExecHook single-step** | ~3000 cycles per hook fire | EPT re-map + #DB single-step + re-strip — per-execution-fault cost |
| **Snapshot** | ~10-100ms depending on VCPU count | WHvGetVirtualProcessorRegisters × num VCPUs + memory region enumeration |

### Why WHP has near-zero overhead

WHP uses Intel VT-x hardware virtualization. When `WHvRunVp` is called, the CPU enters VMX non-root mode and executes the guest code **natively** — `mov`, `add`, `cmp`, SSE/AVX, and most syscall instructions run at full speed with zero interpretation. Only CPUID, RDTSC, MSR access, and HLT cause VM exits (~1000-3000 cycles each). During normal execution, zero exits occur.

---

## Limitations

- **WHP `WHvCreatePartition` requires Hyper-V Platform enabled** — otherwise returns `0xC0351000`
- **KUSER_SHARED_DATA at `0x7FFE0000`** works via EPT (WHP) only; VEH fallback available but less transparent
- **IAT/EAT patching** applies to modules loaded after engine init; pre-loaded system DLLs use proxy DLL shims
- **GPU-intensive workloads** pass through via GpuBridge (always fall through to real GPU)
- **Denuvo hardening (Phases 1-4)**: syscall, MSR, CR4, RDTSC, VEH stack, WMI, registry, and config-gating measures are implemented to defeat Denuvo's hypervisor detection. Phase 3b (registry path filtering) reads guest memory directly — requires identity-mapped GPA=VA layout. Phase 2a (RDTSC compensation) uses a fixed 80-cycle bare-metal CPUID cost, which may need per-SKU tuning
- **SystemSpoofer VEH** uses INT3 patches for SGDT/SIDT/SLDT/STR/XGETBV — may be detected by anti-tamper (gated behind config, off by default for Denuvo)
- **Forward table arg counts** — unknown syscalls default to 4 args; if a >4-arg syscall is missing from the table, the forwarded call will read garbage from the stack
- **Context capture via RtlCaptureContext** captures at Engine_VcpuEntry, not at the original game entry point. RSP is inside Engine_VcpuEntry's frame, not the loader's initial stack. For modern MSVC CRT startups using PEB-based init this works; if issues arise, an assembly register-save stub is needed
- **Denuvo persistent blacklist** — after WHP is detected once, Denuvo persists state across launches. Cleanup functions delete cache files in `game_dir`, `%appdata%\Denuvo\`, and `%TEMP%\dns*`
- **Proxy DLLs use clean system names** loaded with absolute paths via `LoadLibraryW`; GetProcAddress hook uses engine-registered function table
- **WHP-only host machines** — game must have WHP available. No fallback to pure emulation
- **BEL is always active** — KernelLock is acquired/released around every HandleExit call. The lock is non-recursive; asserts in debug builds catch accidental re-acquisition. Single-VCPU workloads see zero contention
- **EptExecHook snapshot serialization** saves only GPA lists; callbacks (std::function) are not serializable — they must be re-registered by the owning code after Restore
- **DXVK passthrough** only pre-loads DXVK DLLs — the actual DXVK binaries must be present in the game directory or provided via `InstallDxvkDlls()`. Does not bundle DXVK itself
- **Snapshot memory regions** save only metadata (GPA, size, flags) — page content is not included. On restore, EPT is rebuilt on-demand by MapDynamicPage. Full memory content snapshot would require 2× memory usage and is not implemented
- **Single VCPU by default** — child thread VCPU migration (Phase 6) is code-complete but gated behind `cpu_count > 1` in config and `SetChildThreadMigrationEnabled(true)`. Without these, child threads run as native host threads outside WHP
- **Syscall number stability** — SSNs vary across Windows builds; dynamic detection from ntdll handles this, but any run-time resolution failure causes the engine to fall back to forwarding
- **WatchdogTracker** relies on non-image memory detection (`IsLikelyWatchdog` returns true for any `MEM_PRIVATE` region) — may generate false positives for legitimate JIT allocators (e.g., .NET, JS engines). Future work: CRC32/checksum pattern matching on watchdog page contents
- **EptSplitView** unmaps/remaps GPA ranges via `WHvMapGpaRange` on each VCPU switch — the ~5000 cycle remap cost adds latency to VCPU migration. For typical 2-4 VCPU workloads this is negligible, but 16+ VCPU configurations may see scheduler latency
- **#VE (Virtualization Exception)** not supported by WHP — requires custom kernel-mode hypervisor driver (SimpleVisor/HyperPlatform pattern) for direct-to-ring-3 EPT violation delivery. Out of ring-3 scope
- **β-time clock correlation** uses a single `SnapshotBaseClocks()` taken at init — long-running sessions (>24h) may accumulate skew between the base reference and real clocks. Future work: periodic re-snapshot or drift compensation from RDTSC reference

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
