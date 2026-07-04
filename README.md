# Symbiote

**Ring-3 Windows userspace hardware fingerprint spoofing framework — educational / security research**

Symbiote is a research platform for studying hardware fingerprinting techniques — how CPUID, MSR, KUSER_SHARED_DATA, WMI, registry, syscalls, and timing can be intercepted and spoofed entirely from user mode **without kernel drivers**. It uses Microsoft's **Windows Hypervisor Platform (WHP)** as its execution backend, with **LSTAR->HLT** syscall interception, **proxy DLLs with IAT patching**, and **SystemSpoofer VEH** for descriptor-table queries.

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
├── Makefile                 # MinGW fallback
├── config/
│   ├── config.ini           # i9-10900K / RX 6800 XT spoof profile
│   ├── config.example.ini   # Example config
│   └── capture.ini          # Capture mode configuration (logs all queries)
├── src/
│   ├── launcher/            # launcher.exe - CLI, process creation, injection
│   ├── engine/              # engine.dll - WHP + VEH + IAT + syscall emulation
│   │   ├── kernel/          # MinimalKernel, SystemProfile, KernelBackend
│   │   ├── whp/             # WHP partition, CPUID/RDTSC/MSR/EPT, AllocTracker, MagicCpuid, Canary, TimingCoordinator
│   │   ├── emu/             # Syscall emulators (Process, Memory, Registry, ...)
│   │   ├── proxy/           # IAT patching, inline hooks, SyscallBridge, GpuBridge
│   │   ├── profile/         # GPU/Storage profiles
│   │   └── log/             # Logger subsystem
│   └── proxydlls/           # 13 proxy DLL shims (ntdll to ws2_32)
├── tools/
│   ├── handshake_test/      # Magic CPUID handshake verification tool
│   ├── capture/             # Standalone capture tool (logs all fingerprint queries)
│   └── msr_reader/          # MSR reader (requires semav6msr64 kernel driver)
├── scripts/
│   └── build.bat            # Full build pipeline
├── docs/
│   ├── RESULTS.md           # Real vs spoofed comparison
│   ├── TECHNIQUES.md        # Per-vector spoofing explainers
│   └── ARCHITECTURE.md      # Research architecture
```

---

## Architecture

```
Target Process (Ring 3)
  Proxy DLLs (clean names)  -->  engine.dll (IAT + LSTAR->HLT)
  kernel32, ntdll, ...            RegisterProxyFunctions, KuserHook
  wbem, ws2_32, ...               AllocTracker, GpuBridge
                                      |
                                SyscallDispatch --> MinimalKernel (via WHP)
                                      |                  |
                                      |            +-----+------+
                                      |            | emulator   |
                                      |            | Process    |
                                      |            | Memory     |
                                      |            | Registry   |
                                      |            | File       |
                                      |            | Timing     |
                                      |            | Crypto     |
                                      |            | Thread     |
                                      |            +------------+
                                      |
                                WHP VCPU (CPUID/RDTSC/MSR/EPT)
                                LSTAR->HLT (syscall intercept via VM exit)
                                SystemSpoofer VEH (SGDT/SIDT/SLDT/STR/XGETBV)
                                      |
                                Real Windows Kernel + GPU (native passthru)
```

### Components

| Component | Role |
|-----------|------|
| **launcher.exe** | Creates target suspended, injects `engine.dll`, calls `Engine_Init`, resumes |
| **engine.dll** | Core engine — WHP partition, IAT patching, LSTAR->HLT syscall intercept, guard-page VEH |
| **Proxy DLLs** (13) | IAT interceptors using clean system DLL names (`kernel32.dll`, `ntdll.dll`, etc.) — route API calls through engine or fall through to real system |
| **MinimalKernel** | Unified syscall dispatcher owning all emulator instances for capture mode |
| **SystemProfile/KernelBackend** | IKernelBackend interface providing CPUID leaves, TSC frequency/offset, processor count, brand string |
| **Syscall Emulators** (emu/) | Per-subsystem handlers: Process, Memory, File, Timing, Registry, Crypto, Thread, Section, Object, VirtualState |
| **WHP VCPU** | Hyper-V partition for CPUID/RDTSC/MSR/EPT exit handling; LSTAR->HLT page for syscall VM exits |
| **AllocTracker** | Guard-page VEH + timer for allocated (JIT) memory CPUID interception |
| **GpuBridge** | GPU DLL passthrough — GPU-intensive calls always go to real system |
| **MagicCpuid** | Handshake protocol (15 leaves, gated behind config `[magic] status=0` by default) |
| **TimingCoordinator** | Cross-handler timing pattern detection (RDTSC→CPUID→RDTSC), three jitter strategies (uniform/constant/linear), monotonic TSC invariant |
| **Canary** | Guard-page memory scanner detector with VEH callback; 4KB handshake page for engine-target coordination |
| **SystemSpoofer** | VEH-based interception of SGDT/SIDT/SLDT/STR/XGETBV — VirtualQuery address walk with MEM_IMAGE exclusion |
| **SyscallDispatch** | Centralized syscall dispatch layer for capture/emulation coordination (used by LSTAR->HLT handler) |
| **CaptureLogger** | Records all fingerprinting queries (CPUID, MSR, RDTSC, syscalls) to disk for analysis |
| **RegisterProxyFunctions** | Engine→proxy API for GetProcAddress hook table population (avoids name-based module lookup on renamed proxies) |

---

## Fingerprint Vectors Covered

| Vector | Interception Method | Status |
|--------|-------------------|--------|
| CPUID leaves (0x0-0x40000000) | WHP exit handler (VCPU only) | Done |
| CPUID extended leaves (0x80000000+) | WHP exit handler (VCPU only) | Done |
| CPUID brand string (0x80000002-4) | CpuidHandler + config-driven brand string | Done |
| CPUID from JIT/allocated memory | AllocTracker guard-page VEH + full register emulation | Done |
| RDTSC / RDTSCP | WHP exit handler (VCPU only) | Done |
| RDTSC→CPUID→RDTSC timing patterns | TimingCoordinator cross-handler detection + delta normalization | Done |
| MSRs (IA32_PLATFORM_ID, FEATURE_CONTROL, etc.) | WHP MsrHandler (VCPU only) | Done |
| KUSER_SHARED_DATA (0x7FFE0000) | EPT hook + shared memory | Done |
| Processor brand string | Registry (NtOpenKey + RegQueryValueExW) + CPUID leaves 0x80000002-4 | Done |
| ACPI MADT (processor count) | Syscall intercept on NtQuerySystemInformation | Done |
| SMBIOS / DMI | Syscall intercept | Done |
| WMI (Win32_Processor, Win32_VideoController) | wbem_proxy COM wrapper (27-method IWbemClassObject) | Done |
| NtQuerySystemInformation | LSTAR->HLT syscall dispatch / SyscallDispatch | In Progress |
| NtQueryInformationProcess | LSTAR->HLT syscall dispatch / SyscallDispatch | In Progress |
| Registry (hardware, processor name) | advapi32_proxy + ntdll_proxy | Done |
| Volume serial / drive info | kernel32 proxy (CreateFileW) | Done |
| Timing analysis | TimingEmu + MinimalKernel timing spoofing | Done |
| PEB / TEB offsets | ProcessEmu via MinimalKernel | Done |
| Network adapter info | iphlpapi_proxy | Done |
| DNS queries | dnsapi_proxy | Done |
| Crypto provider info | crypt32_proxy | Done |
| Session / terminal info | wtsapi32_proxy | Done |
| Security context | secur32_proxy | Done |
| HTTP connections | winhttp_proxy | Done |
| Memory scanner detection | Canary guard-page + VEH callback | Done |
| Target registration / handshake | MagicCpuid (15 leaves, gated behind `[magic] status=0`) | Done |
| SGDT / SIDT / SLDT / STR | SystemSpoofer VEH via VirtualQuery address walk | Done |
| XGETBV (XSAVE feature bits) | SystemSpoofer VEH + config-driven result override | Done |
| RDMSR (ring-3 accessible) | SystemSpoofer VEH (no MsrPatcher) | Done |
| PEB BeingDebugged / NtGlobalFlag | Inline write in engine init | Done |
| CryptGetProvParam (container name) | crypt32_proxy — spoofed unique container UUID | Done |
| GetProcAddress dynamic lookups | kernel32 proxy RegisterProxyFunctions + Proxy_GetProcAddress hook | Done |
| All queries captured to disk | CaptureLogger — enabled via `capture.ini` | Done |

> See `docs/TECHNIQUES.md` for detailed explanations of each vector.
> See `docs/RESULTS.md` for real vs spoofed comparison data.

---

## Build

### Prerequisites

- Windows 10/11 x64 with Visual Studio 2022 C++ workload
- CMake 3.20+
- Windows SDK (includes `WinHvPlatform.h`)
- Optional: Hyper-V + Windows Hypervisor Platform enabled

### MSVC (Recommended)

```bat
:: x64 Release (default)
cmake --preset msvc-x64
cmake --build --preset msvc-x64

:: x64 Debug with verbose logging
cmake --preset msvc-x64-debug
cmake --build --preset msvc-x64-debug

:: x86 Release
cmake --preset msvc-x86
cmake --build --preset msvc-x86
```

### MinGW-w64

```bat
cmake --preset mingw-x64
cmake --build --preset mingw-x64
```

### Build Script

```bat
scripts\build.bat          :: Full clean + build
scripts\build.bat debug    :: Debug build with verbose logging
```

### Output

All binaries go to `build/<preset>/bin/`:

```
engine.dll        - Core spoofing engine
launcher.exe      - Process launcher + injector
verify.exe        - Spoof verification tool (baseline only)
handshake_test.exe - Magic CPUID handshake test tool
capture_tool.exe  - Fingerprint query capture tool
msr_reader.exe    - MSR register reader (requires kernel driver)
kernel32.dll      - Proxy DLL (clean system DLL name)
ntdll.dll         - Proxy DLL
kernelbase.dll    - Proxy DLL
... (13 total, all clean system DLL names)
```

---

## Usage

```bat
launcher.exe --target C:\Path\to\target.exe

:: With verbose debug logging
launcher.exe --debug --target C:\Path\to\target.exe

:: With target arguments
launcher.exe --target target.exe --args --arg1 --arg2

:: Manual arguments
launcher.exe target.exe arg1 arg2
```

---

## Configuration

Default: `config/config.ini` (relative to launcher binary)

Features can be toggled per-section (new format) or via the legacy `[spoof]` section:

```ini
[cpuid]
status = true
vendor = intel
brand_string = Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz

[rdtsc]
status = true

[msr]
status = true

[kuser]
status = true

[process]
status = true

[registry]
status = true

[file]
status = true

[timing]
tsc_frequency = 3696000000
tsc_offset = 0
tsc_noise = 100

[gpu]
vendor = AMD
name = AMD Radeon RX 6800 XT

[system_spoofer]
# SGDT/SIDT/SLDT/STR/XGETBV spoofing
gdt_base = 0x807F900000
gdt_limit = 0xFFFF
idt_base = 0xFFFFF80000000000
idt_limit = 0xFFF
xgetbv_result = 0x0000000000000007

[capture]
# Capture mode: logs all fingerprint queries without spoofing
# Use config/capture.ini to run in capture mode
enabled = false
```

### Capture Mode

To log all fingerprint queries (CPUID, MSR, RDTSC, syscalls) without spoofing:

```bat
copy config\capture.ini config\config.ini
launcher.exe --target C:\Path\to\target.exe
:: Output: capture.log in launcher directory
```

---

## Verification

Tested with engine active (IAT + VEH mode):

| Tool | Result |
|------|--------|
| Coreinfo64 | CPUID signature 000A0655 (i9-10900K), brand spoofed |
| Procmon64 | No registry/file/process leaks detected |
| WinObj64 | No handle leaks |
| handshake_test | All 15 magic CPUID leaves verified, brand string confirmed |

---

## Limitations

- WHP `WHvCreatePartition` may return `0xC0351000` if Hyper-V Platform not enabled
- KUSER_SHARED_DATA at `0x7FFE0000` can't be rewritten from user mode; works via EPT (WHP) only
- IAT patching applies to modules loaded after engine init
- GPU-intensive workloads pass through via GpuBridge (always fall through to real GPU)
- **CodePatcher (UD2+VEH), MsrPatcher (UD2+VEH), InlineHook (INT3) removed** — these were detected by anti-tamper ("rokn")
- **WHP VCPU executes boot code, not the game** — CPUID/RDTSC/MSR intercepts via WHP only fire within VCPU, not on the host. Game runs on host CPU, so WHP exits do not intercept its instructions.
- **LSTAR->HLT syscall infrastructure in place** — every guest SYSCALL inside a VCPU causes a VM exit via HLT page redirect. Requires game execution inside VCPU (WIP: EPT memory mapping for process migration).
- **SystemSpoofer** still uses VEH for SGDT/SIDT/SLDT/STR/XGETBV — SystemSpoofer may be similarly detectable via anti-tamper.
- **Proxy DLLs now use clean system names** (`kernel32.dll`, `ntdll.dll` etc.) via CMake `OUTPUT_NAME`. Loaded with absolute paths via `LoadLibraryW` to bypass KnownDLLs. GetProcAddress hook uses engine-registered function table instead of name-based module lookup.
- AllocTracker VEH emulation uses full register spoofing but does not route through MinimalKernel dispatch
- SystemSpoofer MEM_IMAGE exclusion skips all loaded DLLs — only non-image executable pages are patched for SGDT/SIDT/SLDT/STR/XGETBV
- PEB ProcessHeap.Flags/ForceFlags writes removed (offsets differ per Windows version; BeingDebugged + NtGlobalFlag sufficient)
- **Denuvo persistent state cleanup** added — deletes cache files in game dir, `%appdata%\Denuvo\`, and `%TEMP%\dns*` on cleanup

---

## Performance

| Mode | Execution overhead | Initialization overhead | Mechanism |
|------|------------------|------------------------|-----------|
| **WHP** (VMX non-root, VCPU) | **~0%** | ~50–200 VM exits at ~2000 cycles each | Only CPUID/RDTSC/MSR/HLT cause hardware VM exits; all other instructions run natively on real CPU |
| **SystemSpoofer VEH** (host) | **5–30%+** per patched instruction | Minimal | Each SGDT/SIDT/SLDT/STR/XGETBV triggers kernel exception (5000–10000+ cycles) |

### Why WHP has near-zero overhead

WHP does **not emulate** the target process. It uses Intel VT-x / AMD-V hardware directly. When `WHvRunVp` is called, the CPU enters VMX non-root mode and the process code runs **natively on the real CPU cores** — the same `mov`, `add`, `cmp`, `jmp`, SSE/AVX, and syscall instructions execute at full speed with zero translation or interpretation.

Only three instruction types are configured to cause VM exits:
1. **CPUID** — trapped via VMCS CPUID-interception controls
2. **RDTSC/RDTSCP** — trapped via VMCS TSC-offset / RDTSC-exiting controls
3. **MSR access** — trapped via VMCS MSR-bitmap

Each exit takes ~1000–3000 CPU cycles to handle and return. Since most executable binaries only call these during their initialization phase (typically 50–200 total hits), the cost is negligible — under 400K cycles on a 3–4 GHz CPU.

During normal execution, **zero VM exits occur** for the intercepted instructions if the target doesn't call them in its hot path. The main execution loop runs at bare-metal speed.

### Compare to emulation

| Technique | How it runs code | Overhead |
|-----------|-----------------|----------|
| **Emulation** (QEMU, Unicorn) | Interprets every instruction | 100x–1000x slower |
| **Binary translation** (QEMU TCG, DynamoRIO) | Translates blocks, caches, runs | 2x–10x slower |
| **WHP / VT-x hardware VM** | Native execution on real CPU | **~0%** (exits for specific events only) |

---

## License

This project is open source for fair usage and educational study.

The concept and implementation are the original work of the author. All contributors are recognized as rightful co-owners of their contributions, with equal standing to the original author. The project exists for research purposes only.

See `LICENSE` for full terms.
