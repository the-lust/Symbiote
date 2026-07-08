# Symbiote

**Ring-3 Windows userspace hardware fingerprint spoofing framework — educational / security research**

Symbiote is a research platform for studying hardware fingerprinting techniques — how CPUID, MSR, KUSER_SHARED_DATA, WMI, registry, syscalls, and timing can be intercepted and spoofed entirely from user mode **without kernel drivers**. It uses Microsoft's **Windows Hypervisor Platform (WHP)** as its execution backend, with **EPT process migration (Ghost Sandbox)** for transparent guest execution, **LSTAR->HLT syscall interception with host ntdll forwarding**, **proxy DLLs with IAT/EAT patching**, and **config-gated SystemSpoofer VEH** for descriptor-table queries.

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
├── CMakeLists.txt           # Multi-arch build (MSVC x64/x86, MinGW)
├── CMakePresets.json        # 6 build presets
├── config/
│   └── config.ini           # Dell i7-4510U spoof profile + feature toggles
├── src/
│   ├── launcher/            # launcher.exe — CLI, process creation (suspended), injection, Engine_Init, entry point intercept
│   ├── engine/              # engine.dll — WHP + VEH + IAT/EAT + syscall forwarding + GuestPageTable
│   │   ├── kernel/          # MinimalKernel, SystemProfile, KernelBackend
│   │   ├── whp/             # WHP partition, GuestPageTable, VcpuManager, SyscallDispatch, CPUID/RDTSC/MSR/EPT
│   │   │                    # AllocTracker, MagicCpuid, Canary, TimingCoordinator, SystemSpoofer, ThreadScheduler
│   │   ├── emu/             # Syscall emulators (Process, Memory, Registry, File, Timing, Crypto, Thread, Section, Object)
│   │   ├── proxy/           # IAT/EAT patching, GpuBridge, ModuleCloak, SyscallBridge
│   │   ├── profile/         # GPU/Storage profiles
│   │   └── log/             # Logger subsystem
│   └── proxydlls/           # 13 proxy DLL shims (kernel32, ntdll, kernelbase, advapi32, user32, wbem, wtsapi32, secur32, crypt32, winhttp, dnsapi, iphlpapi, ws2_32)
├── tools/
│   ├── handshake_test/      # Magic CPUID handshake verification tool
│   ├── capture/             # Standalone capture tool (logs all fingerprint queries)
│   └── msr_reader/          # MSR reader (requires semav6msr64 kernel driver)
└── docs/
    ├── RESULTS.md           # Real vs spoofed comparison
    ├── TECHNIQUES.md        # Per-vector spoofing explainers
    └── ARCHITECTURE.md      # Research architecture
```

---

## Architecture

### Current (Ghost Sandbox)

```
Target Process (Ring 3)
  Proxy DLLs (clean names)  ───┐
  kernel32, ntdll, ...          ├── IAT/EAT Patching → engine.dll
  wbem, ws2_32, ...             │       │
                                │       │ (IAT hooks for API-level intercept)
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
  │         ├── LSTAR→HLT page (SYSCALL → VM exit)
  │         ├── WHV_RUN_VP loop:
  │         │     CPUID     → WHP exit   → CpuidHandler       → spoofed values
  │         │     RDTSC     → WHP exit   → RdtscHandler       → spoofed TSC
  │         │     MSR R/W   → WHP exit   → MsrHandler          → spoofed MSRs
  │         │     HLT       → WHP exit   → HandleSyscallExit  → forwarded
  │         │     Mem fault → WHP exit   → MapDynamicPage      → on-demand EPT map
  │         │     #BP/#DB   → WHP exit   → SystemSpoofer VEH
  │         └── Game runs natively inside VCPU (VMX non-root)
  │
  └── Host ntdll (real kernel):
        ├── Forwarded syscalls → host ntdll function → real kernel
        └── Result returned to guest via VCPU registers
```

### Components

| Component | Role |
|-----------|------|
| **launcher.exe** | Creates target suspended, injects `engine.dll`, calls `Engine_Init`, `Engine_InterceptEntryPoint`, resumes |
| **engine.dll** | Core engine — WHP partition, GuestPageTable, VcpuManager, IAT/EAT patching, syscall forwarding |
| **GuestPageTable** | 4-level identity page table builder (PML4→PDPT→PD→PT). Maps GPA=VA for all committed process pages. EPT violation handler for dynamic pages |
| **VcpuManager** | LSTAR→HLT syscall interception, BootstrapFromContext (captured context → VCPU entry), WHP exit dispatch (CPUID/RDTSC/MSR/Memory/Halt/Exception) |
| **SyscallDispatch** | BuildForwardTable (scans ntdll exports → syscall→function map), ForwardSyscall (switch dispatch 0-12 args), spoof handlers for NtQSI/NtQIP |
| **Proxy DLLs** (13) | IAT/EAT interceptors using clean system DLL names (`kernel32.dll`, `ntdll.dll`, etc.) — route API calls through engine or fall through to real system. EAT patching via `IatPatch::PatchEAT` |
| **MinimalKernel** | Unified syscall dispatcher owning all emulator instances for capture mode |
| **SystemProfile/KernelBackend** | IKernelBackend interface providing CPUID leaves, TSC frequency/offset, processor count, brand string |
| **Syscall Emulators** (emu/) | Per-subsystem handlers: Process, Memory, File, Timing, Registry, Crypto, Thread, Section, Object, VirtualState |
| **WHP VCPU** | Hyper-V partition for CPUID/RDTSC/MSR/EPT/Halt exit handling; LSTAR→HLT page for SYSCALL VM exits |
| **AllocTracker** | Guard-page VEH + timer for allocated (JIT) memory CPUID interception |
| **GpuBridge** | GPU DLL passthrough — GPU-intensive calls always go to real system |
| **MagicCpuid** | Handshake protocol (15 leaves, gated behind config `[magic] status=0` by default) |
| **TimingCoordinator** | Cross-handler timing pattern detection (RDTSC→CPUID→RDTSC), three jitter strategies (uniform/constant/linear), monotonic TSC invariant |
| **Canary** | Guard-page memory scanner detector with VEH callback; 4KB handshake page for engine-target coordination |
| **SystemSpoofer** | VEH-based interception of SGDT/SIDT/SLDT/STR/XGETBV — gated behind `[system_spoofer] enabled=false` (default off for Denuvo) |
| **CaptureLogger** | Records all fingerprinting queries (CPUID, MSR, RDTSC, syscalls) to disk for analysis |
| **RegisterProxyFunctions** | Engine→proxy API for GetProcAddress hook table population (avoids name-based module lookup on renamed proxies) |

---

## EPT Process Migration (Ghost Sandbox)

The Ghost Sandbox enables transparent VCPU execution by migrating the game process into a WHP VCPU with identity-mapped guest page tables.

### Flow

```
1. Launcher: CreateProcess(SUSPENDED)
2. Launcher: InjectDll(engine.dll)
3. Launcher: Engine_Init()
   ├── WHP Partition + handlers
   ├── GuestPageTable::Build() → enumerate all committed pages, build 4-level page tables, EPT-map GPA=VA
   ├── VCPU#0 created (not yet running)
   ├── SystemSpoofer (gated by config)
   └── Signal EngineReady
4. Launcher: Engine_InterceptEntryPoint()
   ├── Read PE header → save AddressOfEntryPoint
   └── Write 12-byte trampoline at original entry: mov rax, Engine_VcpuEntry; jmp rax
5. Launcher: ResumeThread()
6. Game thread → hits trampoline → Engine_VcpuEntry()
   ├── RtlCaptureContext (thread registers, RSP, RIP)
   └── VcpuManager::BootstrapFromContext(0, ctx, pageTable)
        ├── CR3 = PML4 GPA (identity-mapped)
        ├── LSTAR→HLT page
        ├── Ring-3 segment registers (CS=0x33, SS=0x2B)
        └── WHvRunVirtualProcessor loop
7. Game runs inside VCPU:
   ├── CPUID → WHP exit → spoofed
   ├── RDTSC → WHP exit → spoofed
   ├── MSR   → WHP exit → spoofed
   ├── SYSCALL → ntdll stub → LSTAR→HLT → HandleSyscallExit
   │     ├── DispatchRawSyscall (NtQSI, NtQIP) → spoofed
   │     └── ForwardSyscall (all others) → host ntdll → real kernel
   ├── Memory fault → MapDynamicPage (on-demand EPT mapping)
   └── Exception → ExceptionHandler
```

### Implementation Phases

| Phase | Component | Status |
|-------|-----------|--------|
| 0 | Config gating: SystemSpoofer/EAT/forwarding toggles | Done |
| EAT | Export Address Table patching (via `IatPatch::PatchEAT`, gated) | Done |
| 1 | GuestPageTable: 4-level identity page table builder + EPT mapping | Done |
| 2 | Entry point interception: PE header trampoline | Done |
| 3 | VCPU Bootstrap: context capture, ring-3 segment/CR/EFER setup | Done |
| 4 | Syscall Forwarding: BuildForwardTable (ntdll export scan), ForwardSyscall (switch 0-12 args) | Done |
| 5 | EPT Violation Handler: on-demand page mapping via MapDynamicPage | Done |
| 6 | Multi-VCPU: child threads via forwarded NtCreateThread | Planned |

### Forward Table

The `SyscallDispatch::BuildForwardTable()` scans all ntdll exports, extracts syscall numbers from function stubs (`mov eax, SSN` pattern), and builds an `unordered_map<uint32_t, ForwardEntry>` with function pointer + arg count. ~90 common syscalls have explicit arg counts; unknown syscalls default to 4 args. The C++ switch dispatch (0-12 args) handles register and stack argument forwarding correctly via function pointer casts.

---

## Fingerprint Vectors Covered

| Vector | Interception Method | Status |
|--------|-------------------|--------|
| CPUID leaves (0x0-0x40000000) | WHP exit handler (VCPU) | Done |
| CPUID extended leaves (0x80000000+) | WHP exit handler (VCPU) | Done |
| CPUID brand string (0x80000002-4) | CpuidHandler + config-driven brand string | Done |
| CPUID from JIT/allocated memory | AllocTracker guard-page VEH | Done |
| RDTSC / RDTSCP | WHP exit handler (VCPU) | Done |
| RDTSC→CPUID→RDTSC timing patterns | TimingCoordinator cross-handler detection | Done |
| MSRs (IA32_PLATFORM_ID, FEATURE_CONTROL, etc.) | WHP MsrHandler (VCPU) | Done |
| KUSER_SHARED_DATA (0x7FFE0000) | EPT hook + shared memory | Done |
| Processor brand string | Registry + CPUID brand leaves | Done |
| ACPI MADT (processor count) | Syscall intercept NtQuerySystemInformation | Done |
| SMBIOS / DMI | Syscall intercept | Done |
| WMI (Win32_Processor, Win32_VideoController) | wbem_proxy COM wrapper | Done |
| NtQuerySystemInformation | LSTAR→HLT → SyscallDispatch | Done |
| NtQueryInformationProcess | LSTAR→HLT → SyscallDispatch | Done |
| Registry (hardware, processor name) | advapi32_proxy + ntdll_proxy | Done |
| Volume serial / drive info | kernel32 proxy | Done |
| Timing analysis | TimingEmu + MinimalKernel | Done |
| PEB / TEB offsets | ProcessEmu via MinimalKernel | Done |
| Network adapter info | iphlpapi_proxy | Done |
| DNS queries | dnsapi_proxy | Done |
| Crypto provider info | crypt32_proxy | Done |
| Session / terminal info | wtsapi32_proxy | Done |
| Security context | secur32_proxy | Done |
| HTTP connections | winhttp_proxy | Done |
| Memory scanner detection | Canary guard-page + VEH callback | Done |
| Target registration / handshake | MagicCpuid (15 leaves, gated behind `[magic] status=0`) | Done |
| SGDT / SIDT / SLDT / STR | SystemSpoofer VEH (gated, default off) | Done |
| XGETBV (XSAVE feature bits) | SystemSpoofer VEH (gated, default off) | Done |
| RDMSR (ring-3 accessible) | SystemSpoofer VEH | Done |
| PEB BeingDebugged / NtGlobalFlag | Inline write in engine init | Done |
| CryptGetProvParam (container name) | crypt32_proxy | Done |
| GetProcAddress dynamic lookups | RegisterProxyFunctions + Proxy_GetProcAddress hook | Done |
| All syscalls via LSTAR→HLT | ForwardSyscall → host ntdll → real kernel | Done |
| All queries captured to disk | CaptureLogger | Done |

---

## Configuration

Default: `config/config.ini` (relative to launcher binary)

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

To log all fingerprint queries without spoofing:
```bat
copy config\capture.ini config\config.ini
launcher.exe --target C:\Path\to\target.exe
```

---

## Build

### Prerequisites

- Windows 10/11 x64 with Visual Studio 2022 C++ workload
- CMake 3.20+
- Windows SDK (includes `WinHvPlatform.h`)
- Optional: Hyper-V + Windows Hypervisor Platform enabled

### MSVC

```bat
:: x64 Release (default)
cmake --preset msvc-x64
cmake --build --preset msvc-x64

:: x64 Debug with verbose logging
cmake --preset msvc-x64-debug
cmake --build --preset msvc-x64-debug
```

### Output

All binaries go to `build/<preset>/bin/`:
```
engine.dll        — Core engine (WHP, GuestPageTable, VcpuManager, SyscallDispatch, proxy)
launcher.exe      — Process launcher + injector + entry point interceptor
verify.exe        — Spoof verification tool
handshake_test.exe— Magic CPUID handshake test tool
capture_tool.exe  — Fingerprint query capture tool
msr_reader.exe    — MSR register reader (requires kernel driver)
kernel32.dll      — Proxy DLL (clean system DLL name)
ntdll.dll         — Proxy DLL (clean system DLL name)
kernelbase.dll    — Proxy DLL (clean system DLL name)
advapi32.dll      — Proxy DLL (clean system DLL name)
... 9 more proxy DLLs (13 total, all clean system DLL names)
```

---

## Limitations

- **WHP `WHvCreatePartition` requires Hyper-V Platform enabled** — otherwise returns `0xC0351000`
- **KUSER_SHARED_DATA at `0x7FFE0000`** works via EPT (WHP) only
- **IAT/EAT patching** applies to modules loaded after engine init
- **GPU-intensive workloads** pass through via GpuBridge (always fall through to real GPU)
- **SystemSpoofer VEH** uses INT3 patches for SGDT/SIDT/SLDT/STR/XGETBV — may be detected by anti-tamper (gated behind config, off by default for Denuvo)
- **Forward table arg counts** — unknown syscalls default to 4 args; if a >4-arg syscall is missing from the table, the forwarded call will read garbage from the stack
- **Context capture via RtlCaptureContext** captures at Engine_VcpuEntry, not at the original game entry point. The RSP is inside Engine_VcpuEntry's frame, not the loader's initial stack. For CRT startups using PEB-based init (modern MSVC), this works; if issues arise, an assembly register-save stub is needed
- **Denuvo persistent blacklist** — after WHP is detected once, Denuvo persists state across launches. Cleanup functions delete cache files in `game_dir`, `%appdata%\Denuvo\`, and `%TEMP%\dns*`
- **Proxy DLLs use clean system names** loaded with absolute paths via `LoadLibraryW`. GetProcAddress hook uses engine-registered function table
- **WHP-only host machines** — game must have WHP available. No fallback to pure emulation
- **Single VCPU** — child threads not yet migrated into VCPUs (Phase 6 planned)

---

## Performance

| Mode | Execution overhead | Mechanism |
|------|-------------------|-----------|
| **WHP VCPU** (VMX non-root) | **~0%** (~50-200 exits × ~2000 cycles each) | Only CPUID/RDTSC/MSR/HALT cause exits; all other instructions run natively |
| **Syscall Forwarding** | Per-syscall: ~2000 cycle exit + function call overhead | Every guest SYSCALL exits via LSTAR→HLT, dispatched to host ntdll |
| **SystemSpoofer VEH** (host) | **5-30%+** per patched instruction | Each SGDT/SIDT/SLDT/STR/XGETBV triggers kernel exception (5000-10000+ cycles) |
| **EPT page fault** | ~5000 cycles on first access | On-demand WHvMapGpaRange for dynamically allocated pages |

### Why WHP has near-zero overhead

WHP uses Intel VT-x hardware virtualization. When `WHvRunVp` is called, the CPU enters VMX non-root mode and executes the guest code **natively** — the same `mov`, `add`, `cmp`, SSE/AVX, and most syscall instructions run at full speed with zero interpretation. Only CPUID, RDTSC, MSR access, and HLT cause VM exits (~1000-3000 cycles each). During normal execution, zero exits occur.

---

## License

This project is open source for fair usage and educational study.

The concept and implementation are the original work of the author. All contributors are recognized as rightful co-owners of their contributions, with equal standing to the original author. The project exists for research purposes only.

See `LICENSE` for full terms.
