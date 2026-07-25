# Symbiote

**Ring-3 Windows userspace hypervisor framework — educational / security research**

Symbiote is a research hypervisor that runs a target process inside a Hyper-V VCPU created via Microsoft's **Windows Hypervisor Platform (WHP)**, intercepting every CPUID, MSR, RDTSC, syscall, memory access, and exception the target generates. It combines WHP's hardware virtualization with 13 user-mode proxy DLLs, syscall emulation, firmware table sanitization, GPU paravirtualization via DXVK, and comprehensive anti-detection coverage spanning 50+ DRM/anti-cheat detection vectors.

> **WARNING: Educational / security research only. Not for anti-cheat bypass or DRM circumvention.**

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        Host Process                              │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  engine.dll                                                 │ │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────────────┐ │ │
│  │  │ WhpBackend  │  │  Unicorn   │  │ ICpuBackend (abstract) │ │ │
│  │  │ (primary)   │  │  Backend   │  │ (fallback)             │ │ │
│  │  └─────┬───────┘  │ (fallback) │  └────────────────────────┘ │ │
│  │        │          └────────────┘                             │ │
│  │  ┌─────┴────────────────────────────────────────────────────┐ │ │
│  │  │  WHP Partition                                           │ │ │
│  │  │  ┌─────────────────────┐  ┌───────────────────────────┐  │ │ │
│  │  │  │ EptMemoryManager    │  │ GuestPageTable            │  │ │ │
│  │  │  │ (on-demand EPT      │  │ (4-level identity-map)    │  │ │ │
│  │  │  │  paging + LRU)      │  │                           │  │ │ │
│  │  │  └─────────────────────┘  └───────────────────────────┘  │ │ │
│  │  │  ┌─────────────────────┐  ┌───────────────────────────┐  │ │ │
│  │  │  │ WorkingSet          │  │ SelectiveExits            │  │ │ │
│  │  │  │ (pre-mapped GPA     │  │ (5 enabled exit types    │  │ │ │
│  │  │  │  ranges, 2MB pages) │  │  for -15-30% throughput) │  │ │ │
│  │  │  └─────────────────────┘  └───────────────────────────┘  │ │ │
│  │  │  ┌─────────────────────┐  ┌───────────────────────────┐  │ │ │
│  │  │  │ VcpuManager         │  │ WhpHiding                 │  │ │ │
│  │  │  │ (LSTAR→HLT syscall  │  │ (13+ detection vectors    │  │ │ │
│  │  │  │  intercept, multi-  │  │  countermeasures)         │  │ │ │
│  │  │  │  VCPU round-robin)  │  └───────────────────────────┘  │ │ │
│  │  │  └──────────┬──────────┘                                 │ │ │
│  │  │             │ Dispatch                                   │ │ │
│  │  │  ┌──────────┴────────────────────────────────────────┐   │ │ │
│  │  │  │  ExitDispatcher                                  │   │ │ │
│  │  │  │  ┌────────────┐ ┌────────────┐ ┌────────────────┐│   │ │ │
│  │  │  │  │CpuidHandler│ │MsrHandler  │ │RdtscHandler    ││   │ │ │
│  │  │  │  │(mask+spoof)│ │(spoof+hide │ │(consistent TSC)││   │ │ │
│  │  │  │  │            │ │ APERF/MPERF│ │                ││   │ │ │
│  │  │  │  └────────────┘ └────────────┘ └────────────────┘│   │ │ │
│  │  │  │  ┌────────────┐ ┌────────────┐ ┌────────────────┐│   │ │ │
│  │  │  │  │EptExecHook │ │System      │ │ExceptionHandler││   │ │ │
│  │  │  │  │(+split-view│ │Spoofer     │ │                ││   │ │ │
│  │  │  │  │ +page prot)│ │(SGDT/SIDT) │ │                ││   │ │ │
│  │  │  │  └────────────┘ └────────────┘ └────────────────┘│   │ │ │
│  │  │  │  ┌────────────┐ ┌────────────┐ ┌────────────────┐│   │ │ │
│  │  │  │  │Consistency │ │AcpiTimer   │ │TimingCoordinator││   │ │ │
│  │  │  │  │Verifier    │ │Handler     │ │(cross-handler  ││   │ │ │
│  │  │  │  │(11 checks) │ │            │ │ pattern detect)││   │ │ │
│  │  │  │  └────────────┘ └────────────┘ └────────────────┘│   │ │ │
│  │  │  └──────────────────────────────────────────────────┘   │ │ │
│  │  │                                                         │ │ │
│  │  │  ┌────────────────────────────────────────────────────┐  │ │ │
│  │  │  │  Sandboxie Isolation Modules                       │  │ │ │
│  │  │  │  VirtualDisk (VHDX/VHD attach/mount)               │  │ │ │
│  │  │  │  FileRedirection (COW + merge enumeration)         │  │ │ │
│  │  │  │  RegistryRedirection (COW + delete marks +         │  │ │ │
│  │  │  │    VM-detection value spoofing)                    │  │ │ │
│  │  │  │  IpcFilter (ALPC/pipe block lists — Denuvo/EAC/BE) │  │ │ │
│  │  │  │  SandboxFallthrough (unified coordinator)          │  │ │ │
│  │  │  └────────────────────────────────────────────────────┘  │ │ │
│  │  │                                                          │ │ │
│  │  │  ┌────────────────────────────────────────────────────┐  │ │ │
│  │  │  │  MinimalKernel — unified syscall dispatcher        │  │ │ │
│  │  │  │  (ProcessEmu, MemoryEmu, FileEmu, RegistryEmu,     │  │ │ │
│  │  │  │   TimingEmu, CryptoEmu, ThreadManager, HwIdEmu,    │  │ │ │
│  │  │  │   MemoryGuardEmu, DeviceIoEmu, PeLoader, etc.)     │  │ │ │
│  │  │  └────────────────────────────────────────────────────┘  │ │ │
│  │  │                                                          │ │ │
│  │  │  ┌────────────────────────────────────────────────────┐  │ │ │
│  │  │  │  EngineExports — C exports for proxy DLLs          │  │ │ │
│  │  │  │  ┌──────────────┐ ┌─────────────────────┐          │  │ │ │
│  │  │  │  │ HwIdEmu (4)  │ │ FirmwareTableSpoofer│          │  │ │ │
│  │  │  │  │ disk/sysinfo │ │ (6 exports: SMBIOS  │          │  │ │ │
│  │  │  │  │ volume serial│ │  + ACPI sanitization)│          │  │ │ │
│  │  │  │  └──────────────┘ └─────────────────────┘          │  │ │ │
│  │  │  │  ┌──────────────┐ ┌─────────────────────┐          │  │ │ │
│  │  │  │  │ IpcFilter (2)│ │ RegistryRedirection │          │  │ │ │
│  │  │  │  │ ALPC/pipe    │ │ (2 exports: redirect │          │  │ │ │
│  │  │  │  │ block queries│ │  + value spoofing)   │          │  │ │ │
│  │  │  │  └──────────────┘ └─────────────────────┘          │  │ │ │
│  │  │  └────────────────────────────────────────────────────┘  │ │ │
│  │  │                                                          │ │ │
│  │  │  ┌────────────────────────────────────────────────────┐  │ │ │
│  │  │  │  GpuBridge → ForwardVulkanIcd + DxvkIntegration    │  │ │ │
│  │  │  │  DXVK detect/install/protect, Vulkan ICD forwarding │  │ │ │
│  │  │  │  VK_ICD_FILENAMES passthrough, Vulkan layer detect  │  │ │ │
│  │  │  └────────────────────────────────────────────────────┘  │ │ │
│  │  └─────────────────────────────────────────────────────────┘ │ │
│  │                                                              │ │ │
│  │  ┌──────────────────────────────────────────────────────────┐ │ │
│  │  │  13 Proxy DLLs — real system DLL shims:                  │ │ │
│  │  │  ntdll (syscall intercept + IPC + firmware + registry),  │ │ │
│  │  │  kernel32, kernelbase, advapi32, user32, wbem (WMI       │ │ │
│  │  │  spoofing), wtsapi32, secur32, crypt32, winhttp,         │ │ │
│  │  │  dnsapi, iphlpapi, ws2_32                                │ │ │
│  │  └──────────────────────────────────────────────────────────┘ │ │
│  │                                                              │ │ │
│  │  launcher.exe — CLI, injects engine.dll into target,        │ │ │
│  │  calls Engine_Init, intercepts entry point,                  │ │ │
│  │  --profile selector for presets + sandbox                    │ │ │
│  └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

| Principle | Implementation |
|-----------|---------------|
| **No INT3 trampolines** | All syscall interception via LSTAR→HLT exclusively — zero `0xCC` writes to executable memory (page hashes never change) |
| **No artificial timing jitter** | JitterDelay() removed from CPUID/MSR handlers — no statistically detectable timing patterns on VM exits |
| **Real system DLLs in guest** | Sogen approach — 13 proxy DLLs forward real system DLL calls, reimplement only what must be spoofed |
| **CPU backend abstraction** | `ICpuBackend` interface: `WhpBackend` (primary, WHP hardware) + `UnicornBackend` (fallback, software-only) |
| **WHP hiding is multi-layer** | 13+ detection vectors covered: CPUID bits, hypervisor leaves, MSR range, RDTSC/RDTSCP timing, Red Pill, SIDT/SGDT/SLDT/STR, ACPI timers, topology, EPT scanning, cache/TLB |
| **DRM countermeasures layered by detection tier** | Tier 1 (CPUID, RDTSC, KUSER, MSR) in WHP backend; Tier 2 (SMBIOS, ACPI, NTDLL, EPT) in proxy DLL exports; Tier 3 (APERF/MPERF, CR4, VMCALL) in handler expansion |
| **SMBIOS/ACPI sanitization** | 6 FirmwareTableSpoofer exports in engine.dll — read real firmware tables via GetSystemFirmwareTable, sanitize VM vendor strings. ntdll_proxy intercepts NtQuerySystemInformation(SystemFirmwareTableInformation) to serve sanitized data |
| **Registry value redirection** | RegRedir_GetRedirectedValue spoofs VM-detection registry values (Hyper-V Installed, BIOSVendor, SystemManufacturer, ProcessorNameString) at the ntdll_proxy NtQueryValueKey hook |
| **APERF/MPERF consistency tracking** | MsrHandler snapshots real APERF/MPERF on init, subtracts VM-exit overhead delta (~1500 cycles + jitter) to maintain ratio matching bare-metal game workloads — evades BattlEye timing analysis |
| **MSR bitmap tuning** | UnhandledMsrs=1 intercepts all MSRs not in explicit whitelist; combined with selective exit config (5 exit types enabled) achieves ~2.3x VM exit reduction vs default WHP configuration |
| **Large page EPT** | MEM_LARGE_PAGES in AllocateGuestMemory + SetupWorkingSet — 2MB pages reduce EPT page walk depth from 4→3 levels, cutting EPT violation exits ~70% |
| **Pre-mapped GPA working set** | 5-region (~16GB) working set allocated and mapped at startup — eliminates runtime EPT violation exits during game loads and dynamic allocation |
| **Process migration** | WinVisor-style — clone target process memory directly into guest via identity-mapped EPT, no kernel driver needed |
| **BEL architecture** | Global exclusive lock (CriticalSection) + per-VCPU shared access for handler thread safety |
| **Sandboxie file/registry isolation** | Copy-on-write path redirection, merge enumeration for reads, delete marks — wired into FileEmu/RegistryEmu syscall dispatch, coordinated by SandboxFallthrough |
| **IPC filtering** | ALPC + named pipe block lists via engine IpcFilter module + ntdll_proxy NtAlpcConnectPort/NtCreateNamedPipeFile hooks — expanded for Denuvo/EAC/BattlEye ports |
| **Virtual disk storage** | VHDX/VHD creation, attach, and volume mount via Win32 virtdisk API as guest-accessible storage backend |
| **HWID spoofing via ring-3** | IOCTL emulation for disk serials, ATA/NVMe identify data, S.M.A.R.T hiding — no kernel driver needed |
| **Memory hiding via syscall dispatch** | PAGE_GUARD tracking at NtProtectVirtualMemory, cross-process read/write filtering at syscall level |
| **GPU paravirtualization via DXVK** | DxvkIntegration detect/install/protect for d3d9/d3d10/d3d11/dxgi + Vulkan ICD forwarding via VK_ICD_FILENAMES — real GPU driver passthrough |
| **Consistency verification** | 11-method ConsistencyVerifier runs runtime assertions: MSR handshake, KUSER tick domain, APERF/MPERF ratio, cross-VCPU time sync, monotonicity, frequency bounds, EPT map integrity, handler dispatch integrity |

## WHP Detection Countermeasures

| Vector | Protection | Module |
|--------|-----------|--------|
| CPUID leaf 1 ECX[31] (hypervisor bit) | Cleared to 0 | CpuidHandler + WhpHiding |
| CPUID 0x40000000-0x400000FF (hypervisor leaves) | All zeros | CpuidHandler + WhpHiding |
| CPUID 0x80000001 ECX[31] | Cleared to 0 | WhpHiding |
| CPUID brand string (0x80000002-0x80000004) | Spoofed "Intel i9-10900K" | CpuidHandler + ntdll_proxy NtQueryValueKey |
| MSR 0x40000000-0x40000FFF (Hyper-V range) | Returns 0 / #GP | MsrHandler + WhpHiding |
| MSR extended range (0xC0000000-0xC0001FFF: EFER, LSTAR, STAR, CSTAR, SFMASK) | Intercepted via UnhandledMsrs=1, dispatch to MsrHandler | Partition + MsrHandler |
| MSR 0x8B (microcode/BiOS_SIGN_ID) | Returns cached real value | MsrHandler + Partition bitmap |
| MSR 0x1A0 (MISC_ENABLE) | Returns real value | MsrHandler + Partition bitmap |
| MSR 0x3A (FEATURE_CONTROL / VMX lock) | #GP injected (bare-metal behavior) | MsrHandler (IsValidMsr check) |
| MSRs 0xFE/0x2FF (MTRR_CAP/MTRR_DEF_TYPE) | Returns spoofed values | MsrHandler |
| MSR 0x10 (TSC) | Consistent TSC, no jitter | RdtscHandler + WhpHiding |
| RDTSC timing (CPUID→RDTSC delta) | < 50000 cycles (no VM exit) | RdtscHandler + CpuidHandler |
| RDTSCP (IA32_TSC_AUX VP index) | Returns 0 | WhpHiding |
| APERF (0xE8) / MPERF (0xE7) consistency | Real HW snapshot on init, VM-exit overhead subtracted (~1500 cycles + jitter) | MsrHandler |
| PERF_FIXED_CTR0/1/2, PERF_GLOBAL_* | Returns 0 (no perf monitoring active) | MsrHandler |
| Red Pill (CR3 comparison) | CR3 reads return same value | WhpHiding |
| SIDT/SGDT/SLDT/STR behavior | EPT execution hook intercept | SystemSpoofer + EptExecHook |
| Cache/TLB topology leaves | Spoofed from real hardware | CpuidHandler |
| ACPI synthetic timer detection | Consistent timer values, HPET counters | AcpiTimerHandler + TimingCoordinator |
| TSC frequency consistency | Matches CPUID leaf 0x15/0x16 | WhpHiding + TimingCoordinator |
| SMBIOS firmware table (NtQuerySystemInformation class 0x16) | Serves sanitized SMBIOS via FwTable_GetSmbios; VM vendor strings zeroed | ntdll_proxy + FwTable_* exports |
| ACPI firmware table (RSDT/DSDT/FACP OEM ID) | Serves sanitized ACPI via FwTable_GetAcpi; OEM ID/Table ID cleaned | ntdll_proxy + FwTable_* exports |
| Registry: HKLM\SOFTWARE\Microsoft\Hyper-V\Installed | Returns DWORD 0 ("not installed") | ntdll_proxy + RegRedir_GetRedirectedValue |
| Registry: HKLM\SOFTWARE\Microsoft\Virtual Machine\Installed | Returns DWORD 0 ("not installed") | ntdll_proxy + RegRedir_GetRedirectedValue |
| Registry: HKLM\HARDWARE\DESCRIPTION\System\BIOS\BIOSVendor | Returns "American Megatrends Inc." | ntdll_proxy + RegRedir_GetRedirectedValue |
| Registry: HKLM\HARDWARE\DESCRIPTION\System\BIOS\SystemManufacturer | Returns "Dell Inc." | ntdll_proxy + RegRedir_GetRedirectedValue |
| Registry: HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0\ProcessorNameString | Returns "Intel i9-10900K @ 3.70GHz" | ntdll_proxy NtQueryValueKey |
| Memory scanning for EPT hooks | No INT3 writes to host pages | All modules |
| Host process/module detection | ModuleCloak + ThreadHider + NtQuerySystemInformation spoofing | proxy + emu |
| Debugger detection (PEB flags) | BeingDebugged=0, NtGlobalFlag=0, heap flags forced | ntdll_proxy FixPebDebugFlags |
| ProcessInstrumentationCallback | Blocked at NtSetInformationProcess level | ntdll_proxy |
| KUSER_SHARED_DATA KdDebuggerEnabled | Set to 0 (disabled) | KuserSync + KuserHook |
| KUSER_SHARED_DATA NtMajorVersion/NtMinorVersion | Consistent with build number | KuserSync |
| ALPC port enumeration | Blocked by IpcFilter at NtAlpcConnectPort (Denuvo/EAC/BE ports) | ntdll_proxy + IpcFilter |
| Named pipe enumeration | Blocked by IpcFilter at NtCreateNamedPipeFile (Denuvo/EAC/BE ports) | ntdll_proxy + IpcFilter |
| Device path detection (\\.\PhysicalDrive, vmware, vbox) | Blocked at NtCreateFile | ntdll_proxy |
| Storage IOCTL queries | Spoofed vendor/product/serial via HwIdEmu | FileEmu + HwIdEmu |
| Cross-process memory reads | Blocked on guarded regions via MemoryGuardEmu | MinimalKernel + MemoryGuardEmu |
| WMI queries (Win32_Processor, Win32_DiskDrive, Win32_BIOS, etc.) | COM wrapping returns configurable spoofed values | wbem_proxy + HwIdEmu |
| DXVK/Vulkan ICD detection | Vulkan layer detection + VK_ICD_FILENAMES forwarding to real host GPU driver | DxvkIntegration + GpuBridge |
| Indirect syscall detection | EPT execute-disable on ntdll syscall page | IndirectSyscall |

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
├── CMakeLists.txt                # 21 targets, /W4 /WX (MSVC), configurable WHP/Unicorn
├── CMakePresets.json             # 6 build presets
├── LICENSE
├── .gitignore
├── config/
│   ├── config.ini                # Active profile + feature toggles
│   ├── config.example.ini        # Example configuration
│   └── capture.ini               # Capture mode (all interception disabled)
├── profiles/                     # Pre-configured .ini profiles for --profile selector
├── docs/
│   ├── ARCHITECTURE.md           # Architecture overview
│   ├── TECHNIQUES.md             # Per-vector analysis deep dives
│   ├── RESULTS.md                # Real vs spoofed comparison
│   └── RESEARCH.md               # Research areas and future directions
├── scripts/
│   ├── build.bat                 # Build helper
│   └── setup-dev.ps1             # Dev environment provisioning
├── tools/
│   ├── handshake_test/           # CPUID handshake protocol test
│   ├── virtualdisk_test/         # Storage IOCTL / volume info spoofing test
│   ├── capture/                  # Standalone fingerprint capture tool
│   ├── msr_reader/               # MSR register reader (requires driver)
│   └── test_sections.ps1         # Section-by-section test script
└── src/
    ├── launcher/                 # launcher.exe — CLI, process creation, engine injection
    ├── engine/                   # engine.dll — core hypervisor engine
    │   ├── whp/                  # 36 modules: Partition, VcpuManager, CpuidHandler,
    │   │                         #   MsrHandler, RdtscHandler, WhpHiding, Ept*,
    │   │                         #   KuserSync/Hook, ConsistencyVerifier, SystemSpoofer,
    │   │                         #   VirtualDisk, FileRedirection, RegistryRedirection,
    │   │                         #   IpcFilter, SandboxFallthrough, Snapshot, ...
    │   ├── backend/              # ICpuBackend + WhpBackend + UnicornBackend
    │   ├── kernel/               # MinimalKernel + KernelBackend + SystemProfile
    │   ├── emu/                  # 17 syscall emulators (Process, Memory, File,
    │   │                         #   Registry, Timing, Crypto, Thread, HwIdEmu,
    │   │                         #   MemoryGuardEmu, DeviceIoEmu, PeLoader, ...)
    │   ├── proxy/                # 11 modules: IatPatch, InlineHook, GpuBridge,
    │   │                         #   DxvkIntegration, SyscallBridge, EngineExports,
    │   │                         #   ModuleCloak, ApiSetResolver, ProxyBase, ...
    │   ├── profile/              # GpuProfile, StorageProfile, TimingProfile
    │   ├── capture/              # CaptureLogger (TSV structured logging)
    │   ├── debug/                # GdbStub (remote debug over TCP :1234)
    │   ├── replay/               # ReplayLogger (deterministic record/replay)
    │   ├── log/                  # Logger subsystem
    │   └── util/                 # HwDetect (TSC, CPU vendor detection)
    ├── proxydlls/                # 13 proxy DLL shims
    │   ├── ntdll_proxy/          # Syscall intercept, IPC filter, firmware table,
    │   │                         #   registry redirection, PEB fix
    │   ├── wbem_proxy/           # WMI COM wrapping for Win32_* spoofing
    │   ├── kernel32_proxy/ ...   # Passthrough shims
    │   └── shared/               # ProxyExport.h
    └── verify/                   # verify.exe — 12-phase test suite
```

## Components

| Component | Location | Role |
|-----------|----------|------|
| **launcher.exe** | `src/launcher/` | CLI: creates target suspended, injects engine.dll, calls Engine_Init, registers entry intercept, `--profile` selector for presets + sandbox |
| **engine.dll** | `src/engine/` | Core engine — all hypervisor, emulation, proxy logic |
| **ICpuBackend** | `src/engine/backend/ICpuBackend.h` | Abstract CPU backend interface (run/stop/regs) |
| **WhpBackend** | `src/engine/backend/WhpBackend.cpp/.h` | Primary CPU backend — WHP hardware virtualization |
| **UnicornBackend** | `src/engine/backend/UnicornBackend.cpp/.h` | Fallback CPU backend — Unicorn1 emulation |
| **Partition** | `whp/Partition.cpp/.h` | WHP partition lifecycle, MSR bitmap, exception bitmap, working set pre-map (5 regions), selective exit config (5 of 17 exit types), on-demand EPT paging, deferred map coalescing, 2MB large pages |
| **GuestPageTable** | `whp/GuestPageTable.cpp/.h` | 4-level identity-mapped page tables |
| **VcpuManager** | `whp/VcpuManager.cpp/.h` | VCPU lifecycle, LSTAR→HLT syscall dispatch, multi-VCPU round-robin scheduling |
| **SyscallDispatch** | `whp/SyscallDispatch.cpp/.h` | Syscall number detection, BuildForwardTable, host ntdll forwarding |
| **SyscallTables** | `whp/SyscallTables.cpp/.h` | Static SSN tables (no runtime NtQuerySystemInformation) |
| **CpuidHandler** | `whp/CpuidHandler.cpp/.h` | CPUID exit handler — all standard/extended leaves (0–0x8000001F), hypervisor masking, brand string spoofing |
| **RdtscHandler** | `whp/RdtscHandler.cpp/.h` | RDTSC/RDTSCP exit handler with consistent monotonic timing |
| **MsrHandler** | `whp/MsrHandler.cpp/.h` | MSR read/write exit handler — extended-range MSR dispatch, APERF/MPERF consistency tracking (real HW snapshot + VM-exit overhead subtraction), PERF_FIXED_CTR/PERF_GLOBAL spoofing |
| **WhpHiding** | `whp/WhpHiding.cpp/.h` | Comprehensive WHP detection countermeasures (13+ vectors) |
| **EptHook** | `whp/EptHook.cpp/.h` | Generic EPT violation handler (kernel memory, MSR bitmap) |
| **EptExecHook** | `whp/EptExecHook.cpp/.h` | EPT-based execution hook with single-step, split-view, page protection |
| **EptMemoryManager** | `whp/EptMemoryManager.cpp/.h` | On-demand EPT page-in with LRU eviction, pre-mapped ranges |
| **EptSplitView** | `whp/EptSplitView.cpp/.h` | Per-VCPU memory view switching for execute-disconnect hiding |
| **EptPageProtect** | `whp/EptPageProtect.cpp/.h` | EPT page permission hooks |
| **SystemSpoofer** | `whp/SystemSpoofer.cpp/.h` | EPT-based SGDT/SIDT/SLDT/STR/XGETBV interception |
| **KuserSync** | `whp/KuserSync.cpp/.h` | KUSER_SHARED_DATA WHP sync thread — consistent tick count, time fields, KdDebuggerEnabled=0 |
| **KuserHook** | `whp/KuserHook.cpp/.h` | KUSER_SHARED_DATA VEH overlay (non-WHP fallback) |
| **MagicCpuid** | `whp/MagicCpuid.cpp/.h` | 15-leaf CPUID handshake protocol (gated) |
| **TimingCoordinator** | `whp/TimingCoordinator.cpp/.h` | Cross-handler RDTSC→CPUID→RDTSC pattern detection, TSC frequency consistency |
| **AcpiTimerHandler** | `whp/AcpiTimerHandler.cpp/.h` | Synthetic ACPI PM timer + HPET counter |
| **IndirectSyscall** | `whp/IndirectSyscall.cpp/.h` | EPT execute-disable on ntdll syscall page |
| **KernelLock (BEL)** | `whp/KernelLock.cpp/.h` | Global exclusive + per-VCPU shared SRW lock |
| **Snapshot** | `whp/Snapshot.cpp/.h` | Sub-ms VCPU+handler state save/restore (no file I/O) |
| **ConsistencyVerifier** | `whp/ConsistencyVerifier.cpp/.h` | Runtime consistency assertions (11 checks: MSR handshake, KUSER tick domain, APERF/MPERF ratio, cross-VCPU time sync, monotonicity, frequency bound, EPT map integrity, handler dispatch integrity) |
| **ThreadScheduler** | `whp/ThreadScheduler.cpp/.h` | Round-robin multi-VCPU coordinator |
| **WatchdogTracker** | `whp/WatchdogTracker.cpp/.h` | Threaded integrity watchdog |
| **ExitDispatcher** | `whp/ExitDispatcher.cpp/.h` | WHP exit reason dispatch routing |
| **ExceptionHandler** | `whp/ExceptionHandler.cpp/.h` | WHP VP exception handler (#BP, #DB, #UD, #PF, #MF, #XM) |
| **AllocTracker** | `whp/AllocTracker.cpp/.h` | Guard-page JIT memory monitor |
| **Canary** | `whp/Canary.cpp/.h` | Guard-page memory scanner detector |
| **VeSimulation** | `whp/VeSimulation.cpp/.h` | Virtual-Exemption simulation for EPT |
| **VirtualDisk** | `whp/VirtualDisk.cpp/.h` | VHDX/VHD creation, attach, detach, volume mount via virtdisk API |
| **FileRedirection** | `whp/FileRedirection.cpp/.h` | File COW + merge path enumeration — wired into FileEmu dispatch |
| **RegistryRedirection** | `whp/RegistryRedirection.cpp/.h` | Registry COW + merge + delete marks + VM-detection value spoofing (GetRedirectedValue returns spoofed Hyper-V, BIOS, manufacturer values) |
| **IpcFilter** | `whp/IpcFilter.cpp/.h` | ALPC/pipe blocking — expanded for Denuvo (DenuvoToken, Client), EAC (EasyAntiCheat, EACService), BattlEye (BEDaisy, BEService), VM detection (vmdetect, hyperv_check, antivm) |
| **SandboxFallthrough** | `whp/SandboxFallthrough.cpp/.h` | Unified coordinator — file/registry/IPC dispatch routing + config init |
| **MinimalKernel** | `kernel/MinimalKernel.cpp/.h` | Unified syscall dispatcher + syscall emulator router (routes to ProcessEmu, MemoryEmu, FileEmu, RegistryEmu, TimingEmu, CryptoEmu, ThreadManager, HwIdEmu, MemoryGuardEmu, DeviceIoEmu) |
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
| **HwIdEmu** | `emu/HwIdEmu.cpp/.h` | Storage HWID spoofing: disk serials, volume serials, ATA/NVMe pass-through, S.M.A.R.T hiding, BIOS/baseboard/chassis serial |
| **MemoryGuardEmu** | `emu/MemoryGuardEmu.cpp/.h` | PAGE_GUARD tracking + cross-process read/write filtering at syscall level |
| **IatPatch** | `proxy/IatPatch.cpp/.h` | IAT + EAT patching with ApiSet resolution |
| **InlineHook** | `proxy/InlineHook.cpp/.h` | 12-byte jmp hooks |
| **GpuBridge** | `proxy/GpuBridge.cpp/.h` | GPU DLL passthrough, ForwardVulkanIcd, DXGI adapter spoofing |
| **DxvkIntegration** | `proxy/DxvkIntegration.cpp/.h` | DXVK detect/install/protect, Vulkan layer detection, Vulkan ICD forwarding (GetHostVulkanIcdPath, SetVulkanIcdEnvironment — finds real NVIDIA/AMD/Intel ICD JSON, sets VK_ICD_FILENAMES) |
| **SyscallBridge** | `proxy/SyscallBridge.cpp/.h` | Syscall forwarding bridge (RouteSyscall export) |
| **EngineExports** | `proxy/EngineExports.cpp/.h` | 13 C-style exports for proxy DLLs: HwIdEmu(4), FirmwareTableSpoofer(6: GetSmbios, GetAcpi, GetFirmware, SanitizeSmbios, SanitizeAcpi), RegistryRedirection(2: ShouldRedirect, GetRedirectedValue), IpcFilter(2: ShouldBlockAlpc, ShouldBlockPipe) |
| **ModuleCloak** | `proxy/ModuleCloak.cpp/.h` | Module hiding from PEB LDR lists |
| **ApiSetResolver** | `proxy/ApiSetResolver.cpp/.h` | ApiSet schema parser from PEB |
| **ProxyBase** | `proxy/ProxyBase.cpp/.h` | Common proxy DLL infrastructure |
| **Fallthrough** | `proxy/Fallthrough.cpp/.h` | Export fallthrough helper |
| **InstructionDecoder** | `proxy/InstructionDecoder.cpp/.h` | x86 instruction length decoder |
| **CaptureLogger** | `capture/CaptureLogger.cpp/.h` | Structured TSV capture log |
| **GpuProfile** | `profile/GpuProfile.cpp/.h` | GPU identity profile |
| **StorageProfile** | `profile/StorageProfile.cpp/.h` | Storage device profile |
| **TimingProfile** | `profile/TimingProfile.cpp/.h` | Timing calibration profile |
| **HwDetect** | `util/HwDetect.h` | TSC frequency, CPU vendor/feature detection |
| **Logger** | `log/Logger.cpp/.h` | Logging subsystem with trace levels (LOG_WHP, LOG_PROXY, LOG_EMU, LOG_DEBUG) |
| **Proxy DLLs** (13) | `proxydlls/*/` | Real system DLL shims: ntdll (syscall+IPC+firmware+registry), kernel32, kernelbase, advapi32, user32, wbem (WMI spoofing), wtsapi32, secur32, crypt32, winhttp, dnsapi, iphlpapi, ws2_32 |
| **verify.exe** | `src/verify/` | 12-phase test suite: CPUID, RDTSC, MSR, KUSER, syscalls, PEB, registry, WMI, network, firmware tables, registry redirection, performance counters |
| **capture_tool** | `tools/capture/` | Standalone fingerprint capture tool |
| **handshake_test** | `tools/handshake_test/` | CPUID handshake protocol test |
| **virtualdisk_test** | `tools/virtualdisk_test/` | Storage VHDX mount/IOCTL test |
| **msr_reader** | `tools/msr_reader/` | MSR register reader (requires semav6msr64 driver) |

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
[hwid_spoofing]      enabled = true          ; Storage HWID spoofing (HwIdEmu)
[memory_guard]       enabled = true          ; PAGE_GUARD memory hiding (MemoryGuardEmu)
[vm]                 cpu_count = 2           ; Virtual CPU count
```

## Sandbox Profiles

Inspired by [RedSand](https://github.com/redcode-labs/RedSand)'s `.wsb` profile system, Symbiote provides pre-configured `.ini` profiles for different use cases. Select one via `--profile`:

| Profile | Use Case | Features |
|---------|----------|----------|
| `default` | General purpose | All spoofing on, WHP hiding active |
| `stealth` | Anti-detection testing | Maximum hiding + sandbox isolation + HWID spoofing + memory guard, watchdog off, AllocTracker/SystemSpoofer off |
| `compat` | Compatibility | Minimal interception, sandbox off, HWID/memory guard off, target runs near-natively |
| `analysis` | Reverse engineering | GDB stub + sandbox isolation + HWID/memory guard, capture logging, break on entry |
| `capture` | Fingerprint collection | Log-only mode, sandbox off, no interception |

```bat
launcher.exe --profile stealth --target C:\Path\to\target.exe
launcher.exe --profile analysis --target C:\Path\to\malware.exe
launcher.exe --profile capture --target C:\Windows\System32\notepad.exe
```

Profiles live in `profiles/` — copy and customize to create your own.

Each profile includes an optional `[sandbox]` section enabling Sandboxie-style isolation, plus `[hwid_spoofing]` and `[memory_guard]` sections for hardware identity hiding:

```ini
[sandbox]
enabled = true
box_name = StealthBox

[hwid_spoofing]
enabled = true

[memory_guard]
enabled = true
```

The `stealth` and `analysis` profiles enable sandbox isolation, HWID spoofing, and memory guard by default; `compat` and `capture` keep them disabled for minimal interference.

### Capture Mode

To log all fingerprint queries without interception (for analysis):

```bat
launcher.exe --profile capture --target C:\Path\to\target.exe
```

## Developer Setup

Run once after cloning:

```bat
powershell -ExecutionPolicy Bypass -File scripts\setup-dev.ps1
```

Checks Visual Studio, CMake, Windows SDK, and WHP availability. Modeled after RedSand's OnHost provisioning pattern.

## Related Work

- **[Sogen](https://github.com/hedronium/Sogen)** (3.3k stars) — WHP+Unicorn+KVM backends, real system DLLs in guest, LSTAR→HLT syscall intercept, GDB stub, deterministic replay. Symbiote adopts the same CPU backend abstraction and real-DLL approach. See [Credits](#credits) for full attribution.
- **[WinVisor](https://github.com/ionescu007/winvisor)** (666 stars) — Process cloning directly into WHP guest via identity-mapped EPT. Symbiote's ProcessCloner implements the same technique.
- **[Sandboxie](https://github.com/sandboxie-plus/Sandboxie)** — User-mode API redirection for file, registry, process, and token isolation. Symbiote implements the same patterns directly at the syscall emulation layer: FileRedirection (prefix-based COW + merge enumeration), RegistryRedirection (COW + delete marks), IpcFilter (ALPC/pipe block lists), VirtualDisk (VHDX-backed sandbox storage), and WMI COM interface wrapping for Win32_* class spoofing.
- **[RedSand](https://github.com/redcode-labs/RedSand)** (37 stars) — Pre-built `.wsb` profiles for Windows Sandbox security work. RedSand's profile system inspired Symbiote's `--profile` presets and its OnHost provisioning scripts inspired `scripts/setup-dev.ps1`.
- **[negativespoofer](https://github.com/SamuelTulach/negativespoofer)** — EFI-level SMBIOS table spoofing. Symbiote adapts the technique to ring-3 syscall + IOCTL emulation for SMBIOS, disk serials, and volume info.
- **[mutante](https://github.com/SamuelTulach/mutante)** — Kernel-mode disk serial spoofing and S.M.A.R.T hiding. Symbiote reimplements at the IOCTL dispatch level in FileEmu + HwIdEmu.
- **[MemoryGuard](https://github.com/SamuelTulach/MemoryGuard)** — PAGE_GUARD memory hiding via VirtualProtect. Symbiote extends to syscall-level dispatch filtering in MinimalKernel.
- **[libkrun](https://github.com/containers/libkrun)** — Virtualization library used by native Linux container runtimes. Symbiote adapts libkrun's TSC frequency detection (CPUID 0x15/0x16 + QPC) and CPUID brand string auto-generation for consistent timing.
- **[DXVK](https://github.com/doitsujin/dxvk)** — DirectX-to-Vulkan translation layer. Symbiote's DxvkIntegration handles DXVK DLL passthrough and Vulkan layer detection.
- **[Unicorn Engine](https://github.com/unicorn-engine/unicorn)** — CPU emulation framework (ARM/x86/MIPS). Used as the UnicornBackend software-only fallback when WHP is unavailable.

## Credits

Symbiote builds upon techniques and patterns from the following open-source projects. Full credit to their authors:

| Project | Author | Technique Used | Files |
|---------|--------|---------------|-------|
| **[Sogen](https://github.com/hedronium/Sogen)** | hedronium | CPU backend abstraction (ICpuBackend/WhpBackend/UnicornBackend), LSTAR→HLT syscall intercept, real system DLLs in guest, deterministic replay, GPU paravirtualization via DXVK + Vulkan ICD forwarding, MSR bitmap tuning for 2.3x exit reduction | `ICpuBackend.h`, `WhpBackend.*`, `UnicornBackend.*`, `VcpuManager.*`, `ReplayLogger.*`, 13 proxy DLLs, `Partition.*`, `DxvkIntegration.*` |
| **[WinVisor](https://github.com/ionescu007/winvisor)** | Alex Ionescu | Process memory cloning into WHP guest via identity-mapped EPT | `ProcessCloner.*` |
| **[Sandboxie](https://github.com/sandboxie-plus/Sandboxie)** | sandboxie-plus | File COW + merge enumeration, registry COW + delete marks, ALPC/pipe IPC filtering, VHDX-backed sandbox storage, WMI COM interface wrapping for Win32_* class spoofing | `VirtualDisk.*`, `FileRedirection.*`, `RegistryRedirection.*`, `IpcFilter.*`, `SandboxFallthrough.*`, `ntdll_proxy/dllmain.cpp`, `wbem_proxy/dllmain.cpp` |
| **[RedSand](https://github.com/redcode-labs/RedSand)** | redcode-labs | `.ini` profile system with `--profile` presets, OnHost provisioning pattern | `profiles/*.ini`, `scripts/setup-dev.ps1` |
| **[negativespoofer](https://github.com/SamuelTulach/negativespoofer)** | Samuel Tulach | SMBIOS table spoofing at firmware level — adapted to syscall + firmware table emulation for SMBIOS + ACPI + storage HWID | `HwIdEmu.*`, `EngineExports.*` (FwTable_* exports), `ntdll_proxy/dllmain.cpp` |
| **[mutante](https://github.com/SamuelTulach/mutante)** | Samuel Tulach | Kernel-mode disk serial spoofing (SATA/NVMe), S.M.A.R.T hiding — adapted to IOCTL emulation | `HwIdEmu.*` |
| **[MemoryGuard](https://github.com/SamuelTulach/MemoryGuard)** | Samuel Tulach | PAGE_GUARD memory hiding technique — extended to syscall-level filtering | `MemoryGuardEmu.*` |
| **[libkrun](https://github.com/containers/libkrun)** | containers | TSC frequency auto-detection (CPUID 0x15/0x16 + QPC), CPUID brand string auto-generation | `TimingCoordinator.*`, `CpuidHandler.*` |
| **[DXVK](https://github.com/doitsujin/dxvk)** | doitsujin | DXVK DLL passthrough, Vulkan layer detection and forwarding | `DxvkIntegration.*`, `GpuBridge.*` |
| **[Unicorn Engine](https://github.com/unicorn-engine/unicorn)** | unicorn-engine | CPU emulation framework used as software-only fallback backend | `UnicornBackend.*` |
| **[kov.dev WHP research](https://kov.dev/)** | kov | WHP performance optimization: MSR bitmap tuning (2.3x exit reduction), large pages (70% fewer EPT violations), SSD=off MMIO improvement | `Partition.*` |

### Source-Level Attribution

Every source file that directly implements a technique from an external project includes a `// Credits:` comment at its top linking to the original repository.

## License

This project is open source for fair usage and educational study.

See `LICENSE` for full terms.
