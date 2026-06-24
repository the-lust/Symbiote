# Symbiote

**Ring-3 Windows userspace hardware fingerprint spoofing framework — educational / security research**

Symbiote is a research platform for studying hardware fingerprinting techniques — how CPUID, MSR, KUSER_SHARED_DATA, WMI, registry, syscalls, and timing can be intercepted and spoofed entirely from user mode **without kernel drivers**. It uses Microsoft's **Windows Hypervisor Platform (WHP)** as its primary execution backend, with **VEH (Vectored Exception Handling)** and **IAT patching** as fallback modes.

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
│   └── config.example.ini   # Example config
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
│   └── handshake_test/      # Magic CPUID handshake verification tool
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
  Proxy DLLs (13 shims)  -->  engine.dll (VEH + IAT + inline hooks)
  ntdll, kernel32, ...        CodePatcher, MsrPatcher
  wbem, ws2_32, ...           KuserHook, AllocTracker, GpuBridge
                                    |
                              SyscallBridge --> MinimalKernel::DispatchThunk
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
                              WHP Sidecar VM (CPUID/RDTSC/MSR/EPT)
                              Guard-page VEH (allocated-memory CPUID)
                                    |
                              Real Windows Kernel + GPU (native passthru)
```

### Components

| Component | Role |
|-----------|------|
| **launcher.exe** | Creates target suspended, injects `engine.dll`, calls `Engine_Init`, resumes |
| **engine.dll** | Core engine — WHP partition, VEH handlers, IAT patching, inline hooks, guard-page VEH |
| **Proxy DLLs** (13) | IAT interceptors that route API calls to engine or fall through to real system |
| **MinimalKernel** | Unified syscall dispatcher owning all emulator instances, static DispatchThunk for proxy bridge |
| **SystemProfile/KernelBackend** | IKernelBackend interface providing CPUID leaves, TSC frequency/offset, processor count, brand string |
| **Syscall Emulators** (emu/) | Per-subsystem handlers: Process, Memory, File, Timing, Registry, Crypto, Thread, Section, Object, VirtualState |
| **WHP Sidecar** | Hyper-V partition for CPUID/RDTSC/MSR/EPT exit handling (degrades to VEH if unavailable) |
| **CodePatcher** | UD2 + VEH patches for CPUID/RDTSC/RDTSCP in target `.text` sections |
| **AllocTracker** | Guard-page VEH + timer for allocated (JIT) memory CPUID interception |
| **InlineHook** | x64-safe 12-byte `mov rax,imm64; jmp rax` hook with complete-instruction trampoline |
| **GpuBridge** | GPU DLL passthrough — GPU-intensive calls always go to real system |
| **MagicCpuid** | Handshake protocol (15 leaves): PID registration, syscall handler exchange, enhanced mode toggle, shared memory GPA, quit, HELLO/ACK, GPA get/set |
| **TimingCoordinator** | Cross-handler timing pattern detection (RDTSC→CPUID→RDTSC), three jitter strategies (uniform/constant/linear), monotonic TSC invariant |
| **Canary** | Guard-page memory scanner detector with VEH callback; 4KB handshake page for engine-target coordination |

---

## Fingerprint Vectors Covered

| Vector | Interception Method | Status |
|--------|-------------------|--------|
| CPUID leaves (0x0-0x40000000) | WHP exit handler + VEH CodePatcher | Done |
| CPUID extended leaves (0x80000000+) | WHP exit handler + VEH CodePatcher | Done |
| CPUID brand string (0x80000002-4) | CpuidHandler + config-driven brand string + enhanced mode override | Done |
| CPUID from JIT/allocated memory | AllocTracker guard-page VEH + full register emulation (no UD2) | Done |
| RDTSC / RDTSCP | WHP exit handler + VEH CodePatcher | Done |
| RDTSC→CPUID→RDTSC timing patterns | TimingCoordinator cross-handler detection + delta normalization | Done |
| MSRs (IA32_PLATFORM_ID, FEATURE_CONTROL, etc.) | WHP MsrHandler + MsrPatcher | Done |
| KUSER_SHARED_DATA (0x7FFE0000) | EPT hook + VEH KuserHook + shared memory | Done |
| Processor brand string | Registry (NtOpenKey + RegQueryValueExW) + CPUID leaves 0x80000002-4 | Done |
| ACPI MADT (processor count) | Syscall hook on NtQuerySystemInformation | Done |
| SMBIOS / DMI | Syscall intercept | Done |
| WMI (Win32_Processor, Win32_VideoController) | wbem_proxy COM wrapper (27-method IWbemClassObject) | Done |
| NtQuerySystemInformation | InlineHook on ntdll | Done |
| Process debug flags | InlineHook on NtQueryInformationProcess | Done |
| Registry (hardware, processor name) | advapi32_proxy + ntdll_proxy | Done |
| Volume serial / drive info | kernel32_proxy (CreateFileW) | Done |
| Timing analysis | TimingEmu + MinimalKernel timing spoofing | Done |
| PEB / TEB offsets | ProcessEmu via MinimalKernel | Done |
| Network adapter info | iphlpapi_proxy | Done |
| DNS queries | dnsapi_proxy | Done |
| Crypto provider info | crypt32_proxy | Done |
| Session / terminal info | wtsapi32_proxy | Done |
| Security context | secur32_proxy | Done |
| HTTP connections | winhttp_proxy | Done |
| Memory scanner detection | Canary guard-page + VEH callback | Done |
| Target registration / handshake | MagicCpuid (15 leaves: PID, syscall handler, enhanced mode, SHM, GPA, quit) | Done |

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
*_proxy.dll       - 13 proxy DLL shims
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

```ini
[cpuid]
vendor = intel
brand_string = Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz
enhanced_brand_string =

[gpu]
vendor = AMD
name = AMD Radeon RX 6800 XT

[timing]
tsc_frequency = 3696000000
tsc_offset = 0
tsc_noise = 100
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

- WHP `WHvCreatePartition` may return `0xC0351000` on some systems — engine degrades to VEH + IAT-only mode
- KUSER_SHARED_DATA at `0x7FFE0000` can't be rewritten from user mode; works via EPT (WHP) or shared memory (VEH)
- IAT patching applies to the main EXE only
- GPU-intensive workloads pass through via GpuBridge (always fall through to real GPU)
- LSTAR syscall entry interception requires EPT hook on kernel pages (future work; MagicCpuid exposes LSTAR tracking only)
- AllocTracker VEH emulation uses full register spoofing but does not route through MinimalKernel dispatch

---

## Performance

| Mode | Execution overhead | Initialization overhead | Mechanism |
|------|------------------|------------------------|-----------|
| **WHP** (VMX non-root) | **~0%** | ~50–200 VM exits at ~2000 cycles each | Only CPUID/RDTSC/MSR cause hardware VM exits; all other instructions run natively on real CPU |
| **VEH fallback** (no WHP) | **5–30%+** if CPUID/RDTSC hit during execution | 5–10% during init | Each patched instruction triggers a kernel exception (5000–10000+ cycles) |

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
