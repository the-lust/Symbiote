# Genjutsu

**Ring-3 Windows userspace hardware fingerprint spoofing framework - educational / security research**

Genjutsu is a research platform for studing how environment fingerprinting techniques work (used by DRM, anti-cheat, and software licensing systems) and how they can be spoofed from user mode **without custom kernel drivers**. It demonstrates that every common hardware fingerprint vector (CPUID, MSR, KUSER_SHARED_DATA, WMI, registry, syscalls, timing) can be intercepted and spoofed using only Microsofts **Windows Hypervisor Platform (WHP)** API, **VEH (Vectored Exception Handling)**, **IAT patching**, and **proxy DLL shims**.

This is the first open research project of its kind that documents and implements userspace-only spoofing for the full fingerprint surface used by modern DRM and anti-cheat systems. It exists purely for educational study of detection and anti-detection techniqes in controlled enviroments lol.

> **WARNING: Educational / security research only.** This porject exists to study fingerprinting mechanisms.
> It does NOT support any specific aplication, game, or DRM system.
> I am NOT responsible for anyone who uses this for any porpuse, legal or otherwise.
> If you use this to violate terms of service or copywrite law, that is on you, not me.

---

## Quick Start

```bat
git clone https://github.com/yourname/genjutsu
cd genjutsu
cmake --preset msvc-x64
cmake --build --preset msvc-x64
build\msvc\x64\bin\Release\launcher.exe --target C:\Path\to\target.exe
```

---

## Project Structure

```
genjutsu/
├── CMakeLists.txt           # Multi-arch build (MSVC x64/x86, MinGW)
├── CMakePresets.json        # 6 build presets
├── Makefile                 # MinGW fallback
├── config/
│   ├── config.ini           # i9-10900K / RX 6800 XT spoof profile
│   └── config.example.ini   # Example config
├── src/
│   ├── launcher/            # launcher.exe - CLI, process create, inject
│   ├── engine/              # engine.dll - WHP + VEH + IAT + SoGen
│   │   ├── whp/             # WHP partition, CPUID/RDTSC/MSR/EPT
│   │   ├── sogen/           # Syscall emulator (NtQuery*, NtOpen*)
│   │   ├── proxy/           # IAT patching, inline hooks, GpuBridge
│   │   ├── profile/         # CPU/GPU/Storage/Timing profiles
│   │   └── log/             # Logger subsystem
│   └── proxydlls/           # 13 proxy DLL shims (ntdll to ws2_32)
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
  Proxy DLLs (13 shims)  -->  engine.dll (VEH + IAT hooks)  -->  SoGen Emulator (syscall dispatch)
  ntdll, kernel32, ...        CodePatcher, MsrPatcher            Process, Memory, Registry
  wbem, ws2_32, ...           KuserHook, InlineHook              File, Crypto, Timing
                              GpuBridge
                                    |
                              WHP Sidecar VM (CPUID/RDTSC/MSR/EPT)
                                    |
                              Real Windows Kernel + GPU (native passthru)
```

### Components

| Component | Role |
|-----------|------|
| **launcher.exe** | Creates target suspended, injects `engine.dll`, calls `Engine_Init`, resumes |
| **engine.dll** | Core spoofing engine - WHP partition, VEH handlers, IAT patching, inline hooks |
| **Proxy DLLs** (13) | IAT shims that intercept API calls and route to engine or fall through to real system |
| **SoGen Emulator** | In-process syscall dispatcher - handles NtQuerySystemInformation, NtOpenKey, registry, file I/O |
| **WHP Sidecar** | Hyper-V partition for CPUID/RDTSC/MSR/EPT exit handling (degrades to VEH if unavailable) |
| **CodePatcher** | UD2 + VEH patches for CPUID/RDTSC/RDTSCP in target `.text` section |

---

## Fingerprint Vectors Covered

| Vector | Interception Method | Status |
|--------|-------------------|--------|
| CPUID leaves (0x0-0x40000000) | WHP exit handler + VEH CodePatcher | Done |
| CPUID extended leaves (0x80000000+) | WHP exit handler + VEH CodePatcher | Done |
| RDTSC / RDTSCP | WHP exit handler + VEH CodePatcher | Done |
| MSRs (IA32_PLATFORM_ID, FEATURE_CONTROL, etc.) | WHP MsrHandler + MsrPatcher | Done |
| KUSER_SHARED_DATA (0x7FFE0000) | EPT hook + VEH KuserHook | Done |
| Processor brand string | Registry (NtOpenKey + RegQueryValueExW) + CPUID leaves 0x80000002-4 | Done |
| ACPI MADT (processor count) | Syscall hook on NtQuerySystemInformation | Done |
| SMBIOS / DMI | Syscall intercept | Done |
| WMI (Win32_Processor, Win32_VideoController) | wbem_proxy COM wrapper (27-method IWbemClassObject) | Done |
| NtQuerySystemInformation | InlineHook on ntdll | Done |
| Process debug flags | InlineHook on NtQueryInformationProcess | Done |
| Registry (hardware, processor name) | advapi32_proxy + ntdll_proxy | Done |
| Volume serial / drive info | kernel32_proxy (CreateFileW) | Done |
| Timing analysis | TimingEmu + SoGen timing spoofing | Done |
| PEB / TEB offsets | SoGen ProcessEmu | Done |
| Network adapter info | iphlpapi_proxy | Done |
| DNS queries | dnsapi_proxy | Done |
| Crypto provider info | crypt32_proxy | Done |
| Session / terminal info | wtsapi32_proxy | Done |
| Security context | secur32_proxy | Done |
| HTTP connections | winhttp_proxy | Done |

> See `docs/TECHNIQUES.md` for detailed explanations of each vector.
> See `docs/RESULTS.md` for real vs spoofed comparison data.

---

## Build

### Prerequisites

- Windows 10/11 x64 with Visual Studio 2022 C++ workoad
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
engine.dll       - Core spoofing engine
launcher.exe     - Process launcher + injector
*_proxy.dll      - 13 proxy DLL shims
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
model = 165
stepping = 5

[brand]
processor = Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz

[gpu]
vendor = AMD
name = AMD Radeon RX 6800 XT

[timing]
tsc_frequency = 3696000000
tsc_noise = 100
```

---

## Verified Tools

Tested with engine active (IAT + VEH mode):

| Tool | Result |
|------|--------|
| Coreinfo64 | CPUID signature 000A0655 (i9-10900K), brand spoofed |
| Procmon64 | No registry/file/process leaks detected |
| WinObj64 | No handle leaks |

---

## Limitations

- WHP `WHvCreatePartition` may return `0xC0351000` on some systems - engine degrades to VEH + IAT-only mode
- KUSER_SHARED_DATA at `0x7FFE0000` cant be rewritten from user mode; works via EPT (WHP) or shared memory (VEH)
- IAT patching applies to the main EXE only
- GPU-intensive apps pass through via GpuBridge (always fall through to real GPU)

---

## Related Research

- momo5502/sogen - Syscall emulator (Unicorn + icicle-emu backends)
- x86matthew/WinVisor - WHP user-mode VM (process cloning, PEB/TEB/KUSER management)
- the-lust/Denuvo-Research - DRM fingerprinting analysis & design spec

---

## Special Thanks

Andreh, Daniel Roster, DoctorY, gitgitkit, mojtaba, oureveryday, PRS, SouNobbao, Verix, 0xZeon — thanks for the help with everything.

---

## License

This project is open source for fair usage and educational study.

The concept and implementation are the original work of the author. All contributors are recognized as rightful co-owners of their contributions, with equal standing to the original author. The project exists for research purposes only.

See `LICENSE` for full terms. Third-party research credited in `docs/ARCHITECTURE.md`.
