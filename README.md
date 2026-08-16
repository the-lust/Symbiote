# Symbiote

**A ring-3 Windows research hypervisor for studying anti-tampering and virtualization-detection techniques.**

Symbiote drops a target process into a hardware-virtualized VCPU using Microsoft's [Windows Hypervisor Platform](https://learn.microsoft.com/en-us/virtualization/api/) (WHP) and intercepts every CPUID, MSR, RDTSC, syscall, memory access, and exception it generates. Instead of a kernel driver, it works primarily from user mode: a launcher injects an engine DLL into the target, the engine stands up a WHP partition and identity-maps the process into it, and fifteen small proxy DLLs shim the real system DLLs so most API calls still go straight to Windows — only the handful that would reveal the presence of a hypervisor get intercepted and answered from a configurable profile. A BYOVD bridge (Bring Your Own Vulnerable Driver, **enabled by default**, read-side only, signed third-party driver — never custom kernel code) covers kernel-adjacent reads, and an Xbox GDK proxy DLL (`xgameruntime_proxy`) provides the Xbox-PC runtime facade for Microsoft Store/Xbox Game Pass titles.

It exists to answer a fairly specific question: what does a piece of commercial protection software (DRM, anti-cheat, an EDR agent, a licensing check) actually look at when it's trying to decide whether it's running on real hardware, and what does it take to make those checks come back clean? Each subsystem in this repo corresponds to one class of detection vector — CPUID hypervisor bits, RDTSC timing deltas, KUSER_SHARED_DATA fields, SMBIOS/ACPI tables, WMI queries, registry artifacts — with the interception mechanism and the spoofed response living next to each other so you can read exactly how a given vector is answered.

> **Educational and security-research use only.** This is not a tool for bypassing copy protection, violating a platform's terms of service, or cheating in online games, and it isn't licensed for that. See [License](#license).

### Master plan (all decisions merged in one place)

The canonical engineering plan for "make Symbiote a working engine" lives in **`../../PLAN.md`** (outside the repo, next to the local clone; or look for `PLAN.md` at the same level as `genjutsu/`). Locked decisions: **WS-1 CPUID spoofing and WS-2 KUSER_SHARED_DATA are THE main things** (they gate milestone M1); Xbox facade + BYOVD + proxy DLLs + the minimal emulated kernel (pre-spoofed data **baked in**, built from `config.ini` at boot, game loaded last) are all core; **BYOVD enabled by default**, read-side only; target = **all Win10 + Win11 builds**; **presence hiding** (WHP/Hyper-V/emulation/VM/sandbox detection) is mandatory (WS-10). Workstreams WS-0..WS-10 → milestones M0..M6. Status: **M0 + M1 complete** — WS-1 (CPUID byte-exact + zero-rule), WS-2 (KUSER byte-exact from a real dump incl. ProcessorFeatures, VirtualClock time authority, EPT-owned spoof page) and WS-7 minimal (KUSER consistency gate green on dev machine, leak monitor armed) all done and pushed. Next: **M2 (WS-3 syscall routing audited — mechanism present; WS-6 slimming config-level done) then M3 (WS-4 Xbox facade forward-complete, full entitlement spoof gated on GDK headers + test title).**

---

## Contents

- [Architecture](#architecture)
- [Quick start](#quick-start)
- [Project layout](#project-layout)
- [Components](#components)
- [Building](#building)
- [Configuration](#configuration)
- [Tools, extras & external integration](#tools-extras--external-integration)
- [Sandbox profiles](#sandbox-profiles)
- [Status](#status)
- [Related work](#related-work)
- [License](#license)

---

## Architecture

```mermaid
flowchart TB
    L["launcher.exe\nCLI — orchestrates 8-phase startup:"]
    L -->|"Phase 0: Bake ConfigSnapshot"| C["ConfigSnapshot\nImmutable baked config from INI"]
    L -->|"Phase 1: BYOVD detect"| B["Universal BYOVD scanner\nAuto-detect Intel/ASUS/Razer/MSI/AORUS/EVGA/GMER\nor admin PhysicalMemory fallback"]
    L -->|"Phase 2: Kernel proxy"| K["KernelProxy\nSSDT hooks · EPROCESS sanitizer\nLSTAR monitor · IDT hook\nDriver list hider"]
    L -->|"Phase 3: Sandbox"| S["VHDX mount · File/Reg/IPC redirection"]
    L -->|"Phase 4: WHP partition"| W["Pre-created Partition\nLSTAR→HLT syscall trap (all exit)\nselective EPT 0F 05 exec-intercepts"]
    L -->|"Phase 5: Rename DLLs"| R["ProxyRenamer\n15 DLLs → random 8-hex names"]
    L -->|"Phase 6: Inject engine"| I["engine.dll + ConfigSnapshot\n→ target process"]
    L -->|"Phase 7: Resume"| J["Resume main thread"]
    L -->|"Phase 8: QEMU Tier A/B"| Q
    
    subgraph T["Target process — ring 3"]
        P["15 proxy DLLs (random-named)\nengine.dll"]
        P --> E["engine.dll"]
    end

    E --> W2["WHP partition\nGuestPageTable · VcpuManager\nLSTAR→HLT syscall trap"]
    W2 --> X["ExitDispatcher\nCpuidHandler · MsrHandler · RdtscHandler\nEPT hooks · ExceptionHandler"]
    X --> K2["MinimalKernel\nsyscall dispatch to 17 emulators"]
    K2 --> H["Real Windows kernel + GPU\nfallthrough for non-spoofed syscalls"]

    subgraph B2["Kernel layer (via BYOVD)"]
        KB["KernelProxy\nk_ntoskrnl · k_dxgkrnl · k_win32k\nk_ndis · k_volmgr"]
        KB -.->|"physical memory R/W\nSSDT injection\nEPROCESS sanitization"| H
    end

    subgraph Q["QEMU Two-Tier"]
        QB["Tier B: QemuTableGen\nACPI/SMBIOS table gen\nAlways-on, linked into engine.dll"]
        QA["Tier A: Full Windows guest\nqemu-system-x86_64-whpx\nWindows Lite (~4GB disk, ~1GB RAM)"]
    end
    
    Q -->|"Spoofed firmware tables"| W2
    QB -.->|"Tier B always active"| E
```

`launcher.exe` creates the target suspended, injects `engine.dll`, and calls its exported `Engine_Init`. From there the engine does three things at once: it creates a WHP partition and clones the target's own memory into it via identity-mapped EPT (the same technique [WinVisor](https://github.com/ionescu007/winvisor) uses, so no separate guest image or kernel driver is needed), it installs the proxy DLLs' hooks for the syscalls and API calls that need spoofed answers, and it starts a VCPU per configured core with `SYSCALL` redirected to a page of `HLT` instructions so every syscall the target makes exits back to the engine instead of running natively.

From there, most of the work is exit handling: CPUID/RDTSC/MSR reads get intercepted at the WHP level and answered from the config profile; syscalls that need spoofing (`NtQuerySystemInformation`, registry reads under `HARDWARE\DESCRIPTION`, storage IOCTLs, etc.) get caught by `MinimalKernel`'s dispatcher and routed to one of seventeen small emulator modules; everything else falls through to the real Windows kernel unmodified. The result is a target process that's mostly running for real, with a narrow, auditable set of interception points.

Full write-up: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Per-vector breakdown of what's intercepted and how: [`docs/TECHNIQUES.md`](docs/TECHNIQUES.md). Real-hardware-vs-configured-profile comparison tables: [`docs/RESULTS.md`](docs/RESULTS.md).

### Design decisions worth knowing about

| Decision | Why |
|---|---|
| **No `0xCC` breakpoint hooks anywhere** | Syscall interception is done entirely via LSTAR→HLT redirection at the WHP level, not INT3 patching. Nothing ever writes to executable memory in the target, so a page-hash or CRC check over `.text` sees the same bytes it would on bare metal. |
| **Real system DLLs stay loaded** | The 15 proxy DLLs forward almost everything to the genuine `ntdll.dll`/`kernel32.dll`/etc.; they only intercept the specific exports that need a different answer. A module list walk still finds real Microsoft-signed DLLs at their normal load addresses. |
| **Process migration, not a fresh VM boot** | The target process is created suspended, then its own address space is identity-mapped straight into the WHP guest — no separate guest OS image, no second boot sequence to keep in sync with the host. |
| **Sandboxie-style isolation is a separate, optional layer** | Copy-on-write file/registry redirection and ALPC/pipe filtering live in their own modules (`FileRedirection`, `RegistryRedirection`, `IpcFilter`) coordinated by `SandboxFallthrough`, independent of the hypervisor-detection countermeasures. You can run with sandboxing off and hiding on, or vice versa. |
| **GPU passthrough, not GPU emulation** | `DxvkIntegration`/`GpuBridge` detect and forward to the real GPU driver (with `VK_ICD_FILENAMES` pointed at the genuine Vulkan ICD), rather than trying to virtualize the display adapter. |
| **Large-page EPT + a pre-mapped working set** | Guest memory is mapped in 2MB pages where possible and a working-set region is pre-mapped at startup, cutting the number of runtime EPT-violation exits substantially versus mapping everything on demand in 4KB pages. |
| **Runtime self-checks, not just static config** | `ConsistencyVerifier` runs eleven checks at startup and periodically afterward — MSR handshake, KUSER tick-domain consistency, APERF/MPERF ratio, cross-VCPU time sync, monotonicity, EPT map integrity — to catch a spoofed profile that's internally inconsistent (e.g. a TSC frequency that doesn't match the configured CPUID leaf 0x15/0x16) before something else notices first. |

Full vector-by-vector table (CPUID leaves, MSR ranges, registry keys, firmware tables, and which module answers each one) is in [`docs/TECHNIQUES.md`](docs/TECHNIQUES.md).

---

## Quick start

```bat
git clone https://github.com/the-lust/Symbiote
cd Symbiote
cmake --preset msvc-x64
cmake --build --preset msvc-x64
```

Binaries land in `build/msvc/x64/bin/Release`. Copy `config/config.example.ini` to `config/config.ini`, adjust it for your machine (see [Configuration](#configuration)), then run something under it:

```bat
launcher.exe --target C:\Windows\System32\notepad.exe
```

or run the built-in check suite to see what the current config actually produces:

```bat
verify.exe
```

`verify.exe` runs standalone (no injection) and prints real-vs-expected results for CPUID, RDTSC, MSR, KUSER, syscalls, PEB, registry, WMI, and network vectors — a fast way to sanity-check a profile before pointing the launcher at anything.

---

## Project layout

```
symbiote/
├── CMakeLists.txt              # 25 build targets, /W4 /WX on MSVC
├── CMakePresets.json            # 6 presets (msvc/mingw × x64/x86 × release/debug)
├── LICENSE
├── config/
│   ├── config.example.ini       # Copy to config.ini and edit — see Configuration below
│   └── capture.ini              # Capture-mode profile (logs queries, spoofs nothing)
├── profiles/                    # stealth.ini / compat.ini / analysis.ini / capture.ini
├── docs/
│   ├── ARCHITECTURE.md
│   ├── TECHNIQUES.md            # per-vector deep dive
│   ├── RESULTS.md               # real vs. configured comparison tables
│   └── RESEARCH.md
├── scripts/
│   ├── build.bat
│   └── setup-dev.ps1            # checks VS/CMake/SDK/WHP availability
├── tools/
│   ├── capture/                 # standalone fingerprint capture tool
│   ├── handshake_test/          # CPUID handshake protocol test
│   ├── virtualdisk_test/        # VHDX mount / storage IOCTL test
│   └── msr_reader/               # raw MSR reader (needs a signed driver)
└── src/
    ├── launcher/                 # launcher.exe: process creation, DLL injection
    ├── engine/                   # engine.dll — everything else
    │   ├── whp/                  # partition, VCPUs, EPT, exit handlers, hiding (35 modules)
    │   ├── backend/               # CPU-backend abstraction (WhpBackend + UnicornBackend both usage-ready)
    │   ├── kernel/                # MinimalKernel syscall dispatcher
    │   ├── emu/                  # 17 per-domain syscall emulators
    │   ├── proxy/                 # IAT/EAT patching, inline hooks, GPU bridge, ApiSet resolver
    │   ├── profile/               # GPU/storage/timing identity profiles
    │   ├── capture/               # structured TSV capture logging
    │   ├── debug/                 # GDB stub (TCP :1234)
    │   ├── replay/                # deterministic record/replay
    │   └── log/                  # trace logging
    ├── byovd/                     # BYOVD driver loader + signed third-party driver binary
    ├── proxydlls/                 # 15 proxy DLL shims (ntdll, kernel32, wbem, xgameruntime, ...)
    └── verify/                    # verify.exe check suite
```

> **Note:** there is no `byovd/` directory and **no `.sys` driver binary ships with the repo** (by design — nothing signed gets committed). The BYOVD machinery lives in `src/engine/byovd/` (`ByovdDetect`, 8-driver auto-detection DB) and `src/engine/whp/ByovdDriver.*`; at runtime it locates an already-installed/running signed driver or falls back to admin `\\.\PhysicalMemory`.

---

## Components

| Component | Location | Role |
|---|---|---|
| `launcher.exe` | `src/launcher/` | Creates the target suspended, injects `engine.dll`, calls `Engine_Init`, sets an entry-point trampoline, handles `--profile` |
| `engine.dll` | `src/engine/` | Everything else — hypervisor, syscall emulation, proxy DLL support |
| `Partition` | `whp/Partition.*` | WHP partition lifecycle, MSR bitmap, exception bitmap, working-set pre-map, 2MB large pages, on-demand EPT paging |
| `GuestPageTable` | `whp/GuestPageTable.*` | 4-level identity-mapped guest page tables |
| `VcpuManager` | `whp/VcpuManager.*` | VCPU lifecycle, LSTAR→HLT syscall redirection, round-robin scheduling across VCPUs |
| `SyscallDispatch` / `SyscallTables` | `whp/Syscall*.*` | Runtime SSN detection cross-checked against static per-build tables, host-`ntdll` forwarding |
| `CpuidHandler` / `MsrHandler` / `RdtscHandler` | `whp/*Handler.*` | Exit handlers for their respective instructions — masking, spoofing, APERF/MPERF consistency tracking |
| `WhpHiding` | `whp/WhpHiding.*` | Hypervisor-presence countermeasures that don't fit neatly under one exit handler |
| `EptHook` / `EptExecHook` / `EptMemoryManager` / `EptSplitView` / `EptPageProtect` | `whp/Ept*.*` | EPT violation handling, execution hooks, on-demand paging, per-VCPU memory views, page-permission hooks |
| `SystemSpoofer` | `whp/SystemSpoofer.*` | EPT-based interception of SGDT/SIDT/SLDT/STR/XGETBV |
| `KuserSync` / `KuserHook` | `whp/Kuser*.*` | KUSER_SHARED_DATA consistency: live sync while WHP is active, VEH overlay as a fallback |
| `TimingCoordinator` | `whp/TimingCoordinator.*` | Cross-handler RDTSC/CPUID pattern tracking and TSC-frequency consistency, shared by `CpuidHandler` and `RdtscHandler` |
| `AcpiTimerHandler` | `whp/AcpiTimerHandler.*` | Synthetic ACPI PM timer + HPET counters |
| `KernelLock` | `whp/KernelLock.*` | Global-exclusive / per-VCPU-shared lock serializing handler state access across VCPU threads |
| `Snapshot` | `whp/Snapshot.*` | VCPU + handler state save/restore, in memory, off by default |
| `ConsistencyVerifier` | `whp/ConsistencyVerifier.*` | Eleven runtime self-checks — see [design decisions](#design-decisions-worth-knowing-about) above |
| `ExitDispatcher` / `ExceptionHandler` | `whp/*.* ` | WHP exit-reason routing; guest exception handling (#BP, #DB, #UD, #PF, #MF, #XM) |
| `VirtualDisk` | `whp/VirtualDisk.*` | VHDX/VHD create/attach/mount via the Win32 virtdisk API |
| `FileRedirection` / `RegistryRedirection` | `whp/*Redirection.*` | Copy-on-write file/registry isolation, wired into `FileEmu`/`RegistryEmu` |
| `IpcFilter` | `whp/IpcFilter.*` | Configurable ALPC/named-pipe pattern blocking |
| `SandboxFallthrough` | `whp/SandboxFallthrough.*` | Coordinates the three isolation modules above |
| `MinimalKernel` | `kernel/MinimalKernel.*` | The syscall dispatcher — routes to whichever of the 17 `emu/` modules owns a given syscall |
| `ProcessEmu` / `MemoryEmu` / `FileEmu` / `RegistryEmu` / `TimingEmu` / `CryptoEmu` | `emu/*.*` | Per-domain syscall emulation |
| `ThreadManager` / `ThreadHider` | `emu/*.*` | Thread lifecycle emulation and enumeration filtering |
| `PeLoader` | `emu/PeLoader.*` | PE parsing for process migration — import table, relocations |
| `HwIdEmu` | `emu/HwIdEmu.*` | Disk/volume serials, ATA/NVMe identify data, S.M.A.R.T, BIOS/baseboard/chassis serial |
| `MemoryGuardEmu` | `emu/MemoryGuardEmu.*` | PAGE_GUARD tracking and cross-process read/write filtering at the syscall level |
| `IatPatch` / `InlineHook` | `proxy/*.*` | IAT/EAT patching with ApiSet awareness; trampoline-based inline hooks |
| `ApiSetResolver` | `proxy/ApiSetResolver.*` | Parses the ApiSet schema from the PEB to resolve `api-ms-win-*` contract names |
| `GpuBridge` / `DxvkIntegration` | `proxy/*.*` | Real-GPU-driver passthrough, DXVK detection and Vulkan ICD forwarding |
| `ModuleCloak` | `proxy/ModuleCloak.*` | Unlinks a module from all three PEB loader lists |
| `EngineExports` | `proxy/EngineExports.*` | Sole named export (`Engine_GetExport`) + function address table — proxy DLLs resolve all engine functions by ID; table header written to shared memory at engine init |
| `WhpBackend` / `UnicornBackend` / `ICpuBackend` | `backend/*.*` | CPU-backend abstraction — `WhpBackend` wraps WHP lifecycle, `UnicornBackend` wraps Unicorn Engine (dynamically loaded `unicorn.dll`). Both implement `ICpuBackend`; selectable via `[backend] type=whp|unicorn` in config. |
| `ByovdDriver` | `whp/ByovdDriver.*` | BYOVD driver loader: locate, open, map physical memory, create `\Device\SymbPhysMem`, unload — kernel-memory read access via a signed third-party driver |
| `ByovdDetect` | `engine/byovd/ByovdDetect.*` | 8-driver auto-detection (Intel GPU, ASUS GLCKIo, Razer RzDriver, MSI WinRing0, AORUS, EVGA, GMER, PhyMem), probe-validated capabilities, admin `\\.\PhysicalMemory` fallback |
| Proxy DLLs (15) | `proxydlls/*/` | Shims for `ntdll`, `kernel32`, `kernelbase`, `advapi32`, `user32`, `wbem`, `wtsapi32`, `secur32`, `crypt32`, `winhttp`, `dnsapi`, `iphlpapi`, `ws2_32`, **`xgameruntime`** |
| `verify.exe` | `src/verify/` | Standalone check suite — see [Quick start](#quick-start) |
| `capture_tool` / `handshake_test` / `virtualdisk_test` / `msr_reader` | `tools/*/` | Standalone utilities for fingerprint capture, the CPUID handshake protocol, VHDX/IOCTL testing, and raw MSR reads |

---

## Building

### Prerequisites

- Windows 10/11 x64
- Visual Studio 2022 with the "Desktop development with C++" workload (or MinGW-w64 for the `mingw-*` presets)
- CMake 3.20+
- Windows SDK with `WinHvPlatform.h`/`WinHvPlatform.lib` (included in recent SDK versions)
- Windows Hypervisor Platform enabled — `Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform`, then reboot

### Presets

| Preset | Arch | Config | Compiler |
|---|---|---|---|
| `msvc-x64` | x64 | Release | MSVC |
| `msvc-x64-debug` | x64 | Debug | MSVC |
| `msvc-x86` | x86 | Release | MSVC |
| `msvc-x86-debug` | x86 | Debug | MSVC |
| `mingw-x64` | x64 | Release | MinGW |
| `mingw-x86` | x86 | Release | MinGW |

```bat
cmake --preset msvc-x64
cmake --build --preset msvc-x64
```

`scripts\build.bat` wraps the same commands and accepts `debug`, `x86`, `x86-debug`, `mingw`, `mingw-x64`. All 21 targets build clean under `/W4 /WX` — no suppressed warnings.

### Developer setup

```bat
powershell -ExecutionPolicy Bypass -File scripts\setup-dev.ps1
```

Checks that Visual Studio, CMake, the Windows SDK, and WHP are all present and reports what's missing.

---

## Configuration

Everything is driven by an INI file — `config/config.ini` by default, or whatever `--profile <name>` points at. Start from the example:

```bat
copy config\config.example.ini config\config.ini
```

then edit it. `config.ini` is gitignored deliberately: it's meant to hold your own hardware profile, and real disk serials, MAC addresses, and system UUIDs shouldn't end up in git history.

A profile is organized by vector — `[cpuid]`, `[msr]`, `[kuser]`, `[hardware]`, `[storage]`, and so on — each with a `status`/`enabled` toggle and the values to serve when it's on.

**Stealth is always-on unless turned off.** The shipped default:

```ini
[stealth]
always_on = 1        ; every spoof vector ENABLED unless a section explicitly sets status=0
always_on = 0        ; = full passthrough (a section only spoofs if it explicitly opts in)
```

So you never have to remember to enable vectors — the profile is spoof-first, and the only way a vector leaks is an explicit `status = 0` in its own section (useful for debugging one section at a time). `verify.exe` tells you exactly what's live rather than you having to read the ini.

---

## Tools, extras & external integration

The launcher integrates external tooling without bundling anything — paths come from `[tools]` in `config.ini`, and point at locally installed binaries:

```ini
[tools]
; Steam/SteamStub unpack chain (research use on binaries you own):
steamless = C:\tools\Steamless.exe
gbe = C:\tools\gbe.exe
opensteamtools = C:\tools\OpenSteamTools.exe
steamsls = C:\tools\steamsls.exe
steamvent = C:\tools\steamvent.exe
steamdira = C:\tools\steamdira.exe
; Debuggers / disassemblers / analyzers / tracers:
ce = C:\Program Files\Cheat Engine\cheatengine-x86_64.exe
ghidra = C:\ghidra\support\analyzeHeadless.bat
x64dbg = C:\x64dbg\x64dbg.exe
binja = C:\BinaryNinja\binaryninja.exe
ida = C:\IDA\ida.exe
pin = C:\pin\pin.exe
; AI analyzer — any local model CLI; %REPORT% is replaced with report.json:
ai_analyzer = python tools\ai_analyze.py --llm "ollama run llama3.2"
```

CLI wiring:

| Flag | What it does |
|---|---|
| `--list-tools` | Print the registry with availability (path present?) |
| `--tool <name>` | Run one tool against the target before launch (`launcher.exe --tool steamless --target game.exe`) |
| `--unpack` | Auto-unpack the target through the chain (steamless → gbe → opensteamtools → steamsls → steamvent → steamdira), first success wins, then launch the unpacked exe |
| `--analyze [dir]` | Write `dump/report.json` (target, active spoof vectors, tool coverage, dump file list) and run the AI analyzer |

The AI hook ships as `tools/ai_analyze.py`: fully offline, reads the report, prints a heuristic engineering analysis (leaked vectors, unpacker status, next-step suggestions), and can optionally pipe the report into any local model CLI (`--llm "ollama run llama3.2"`). No cloud APIs, no keys.

### Hypervisor rail (optional, advanced)

```ini
[hypervisor]
mode = whp        ; PRIMARY rail — WHP user-mode hypervisor (default, preferred)
mode = driver     ; OPTIONAL ring -1 driver rail — NOT BUILT YET, fails loud
```

The WHP rail stays the main and primary hypervisor. `mode = driver` reserves an advanced rail for a ring -1 driver backend — SimpleSVM-style on AMD, HyperDbg-style on Intel — that is deliberately not implemented yet: selecting it makes the engine abort init with an explicit error (`hyplog.log`/`launcher.log`) about which backend family your CPU would use, instead of silently running.

---

## Sandbox profiles

`profiles/` holds a few starting points, in the spirit of [RedSand](https://github.com/redcode-labs/RedSand)'s `.wsb` presets:

| Profile | File | What it's for |
|---|---|---|
| *(none)* | `config/config.ini` | Whatever you've configured locally |
| `stealth` | `profiles/stealth.ini` | Maximum hypervisor-transparency + full sandbox isolation |
| `compat` | `profiles/compat.ini` | Minimal interception — closest to running the target natively, useful for isolating whether a problem is Symbiote-induced |
| `analysis` | `profiles/analysis.ini` | GDB stub on, capture logging on, breaks at entry — for stepping through a target under the hypervisor |
| `capture` | `profiles/capture.ini` | Logs every fingerprint query without answering any of them, for building a profile from observed behavior |

```bat
launcher.exe --profile stealth --target C:\Path\to\target.exe
launcher.exe --profile capture --target C:\Windows\System32\notepad.exe
```

Copy one of these to make your own.

---

## Status

Single maintainer, actively worked on, no CI yet. This section is meant to be read before you rely on anything below — it's where the honest gaps live, not just the finished parts.

**What's been hardened:** a fairly extensive correctness pass has gone through the VCPU lifecycle, EPT paging, the PE loader used for process migration, the syscall dispatch tables, and most of the proxy DLLs — fixing a double-free on VCPU teardown, a swapped-argument bug that crashed on an extremely common syscall pattern, an out-of-bounds stack read, unbounded PE-parsing that didn't validate offsets against the target buffer, several unlocked data structures shared across VCPU threads, and a handful of dead code paths that looked wired up but weren't (a save-state feature that could never actually restore anything, a memory-scan detector that was never armed, a patch-application loop that silently stopped after the first skipped region). None of that is meant as a boast — it's a list of the kind of bugs a project like this accumulates fast, and a marker for what's already been looked at closely versus what hasn't.

**What's been recently completed:**

- **M2 lead-in: tools/extras wiring + stealth-default + optional driver rail.** `[stealth] always_on=1` is now the shipped default ("stealth unless turned off" — previously CPUID/RDTSC shipped off); the launcher gained a `ToolKit` (registry + spawn + Steam/SteamStub unpack chain + `--list-tools`/`--tool`/`--unpack`/`--analyze`), an offline AI report analyzer (`tools/ai_analyze.py`, optional local-model `--llm` piping), and `[hypervisor] mode=whp|driver` — the driver rail (SimpleSVM-style AMD / HyperDbg-style Intel) is reserved and fails loud when selected, keeping WHP the main and primary rail. All additions are optional and paths point at locally installed tools; nothing is bundled.
- **M1 exit criteria all met (WS-2/WS-7 closure).** CPUID **and** KUSER are now byte-exact from a real dump: a live `ProcessorFeatures` capture from the donor machine (this machine, Win 11 26200) was verified byte-for-byte against the engine's hex parser (round-trip match) and baked into `config.ini [kuser] processor_features` — closing the last zero-rule placeholder. The KUSER consistency gate ran green against the live host page (all 13 sub-checks), and the leak monitor is armed in the KUSER sync loop.
- **M1/WS-4 forward coverage (Xbox facade).** `xgameruntime_proxy` now exports the full GDK license/entitlement query surface (`XStoreQueryGameLicenseAsync/Result`, `XStoreQueryAddOnLicensesAsync`, `XStoreQueryLicenseTokenAsync/Result`, `XStoreGetLicenseEntitlementIdAsync`, `XStoreGetLicenseSkuIdAsync`) — forwarded to the real `xgameruntime.dll` (present in System32 on Xbox-PC-capable machines) with graceful `E_NOTIMPL` fallback; engine IAT hook table synced to the 16 exports. Fabricated entitlement payloads (productId/skuId/isShared per ini) are deliberately deferred: they need GDK headers and a live test title to avoid lying structs (M3 build-out).
- **M1/WS-3 audit (syscall routing) — mechanism confirmed complete.** WHP has no per-syscall exit bitmap (M0 finding); the shipped stack is: proxy APIs → L2 emulated-kernel path, naked syscalls → LSTAR→HLT at L0, selective interception (5 syscalls emulated natively + thread-management handlers) via `DispatchRawSyscall`, everything else forwarded to host ntdll with runtime SSN detection (`GetSyscallNumber` disassembles the real ntdll stub, cross-checked/corrected against static `SyscallTables`). `handle_overflow` note: ~2000 native fallthrough is the intended design.
- **M1/WS-6 slimming — config-level complete.** Product profile (`config.ini`) has no `[capture]`/`[sandbox]`/replay/GDB sections (all dev-only infra stays off); every active spoof component is explicitly `enabled = false/true` per section and runs gated.

- **M1/WS-2 (KUSER_SHARED_DATA spoofing) — byte-exact modern layout, zero-rule page, clocks consistent by construction.** The KUSER page the guest sees is now a fully engine-owned spoof page, and everything that reports time agrees with it:
  - **`KuserLayout.h` — byte-certified layout.** The 19041+ x64 layout (from shared NT headers, validated field-by-field against a live page dump on Windows 11 build 26200) with `static_assert` on every offset the engine writes. Builds < 19041 use an older, non-certified layout — `KuserSync` refuses to spoof them (fail-loud).
  - **`VirtualClock` — single time authority.** Spoofed RDTSC → QPC-100ns → system time / interrupt time / tick count. KUSER fields, `NtQuerySystemTime` and the synthetic TSC are consistent by construction (the old `NtQuerySystemTime` handler served the *native* system time — a leak vector, now closed). System time is anchored once to the host wall clock (environment, not identity).
  - **EPT ownership.** Guest page tables are identity-mapped, so KUSER GPA == VA == 0x7FFE0000; the host's real KUSER page can never be mapped at that GPA (`GuestPageTable` splits its region map around it) and the spoof mapping is re-asserted after page-table build and periodically by the sync thread.
  - **Zero-rule page.** The spoof page starts fully zeroed; only TIP-config fields and math values are written. Nothing is copied from the host (old `KuserHook` fallback memcpy'd the real page — removed). Optional `processor_features` hex blob for a future real donor dump.
  - **Consistency gate extended (WS-7 minimal).** New `VerifyKuserSelfConsistency` (13 sub-checks: identity sanity, ticking tick count, TickCount↔InterruptTime ratio, SystemTime/TimeZoneBias/InterruptTime plausibility, XState zero-rule integrity); when the spoof is live the KUSER checks validate the spoof page (TIP self-coherence, fail-loud). CPU/memory checks moved to modern offsets and made spoof-aware. All sub-checks verified against the live host page.
  - **Leak monitor (minimal) armed.** The 1ms KUSER sync loop re-asserts the GPA mapping and verifies the zero-rule zone is untouched every ~1s, restoring the page if anything wrote into it.
- **M1/WS-1 (CPUID spoofing) — the frozen profile is now byte-exact and nothing leaks.** This is the first milestone of the master plan (`PLAN.md`, one level above this repo: WS-0..WS-10 → M0..M6). Four parts:
  - **TIP loader fixed.** The `[cpuid]` profile loader had key-name mismatches (queried `leaf_0x4_0_eax`, configs carry `leaf_0x4_sub0_eax`) and never queried leaves 0x5/0x6/0x8/0x9/0xA/0xD at all — so the engine silently served the built-in i9-10900K default profile (20 cores, 3.7GHz leaf 0x16, PMU 0x07300803) instead of the donor's frozen values. The loader now matches all key conventions (plain / `_subN` / `_N`) across flat and sectioned configs (`[cpuid.basic]`, `[cpuid.leaf_4]`, `[cpuid.ext]`, ...), covers the full 0x0..0x1F + 0x80000000..0x80000008 range, and treats **any** `[cpuid]` content as authoritative — the built-in default profile is wiped so no leaf can leak a default CPU's values. Verified byte-exact against a real donor capture (`leaf_0xB` = 2 threads/4 cores, `leaf_0xA` PMU, `leaf_0xD` XSAVE, brand "i7-4510U @ 2.00GHz").
  - **Zero-rule for unlisted leaves.** `CpuidHandler` never answers unlisted leaves from real hardware anymore: a single shared policy path (`EvaluateLeaf`) serves TIP → zero, applies the universal feature mask, clears leaf-1 ECX[31] (hypervisor-present) + ECX[6] (SMX), and clamps max-leaf to the frozen profile (0xD / 0x80000008). The exit path and **both** WHP CPUID result-list builders now use this same policy, so cached and VM-exit-served leaves answer identically. Zero-rule misses are logged (throttled).
  - **Two native-CPUID leak paths closed.** `AllocTracker`'s guard-page VEH answered guest CPUID/RDTSC with real hardware (plus a bare bit-31 clear) — it now routes through the same policy and `RdtscHandler::ReadSpoofedTsc()`. `Partition`'s no-handler result-list fallback no longer serves native leaf 1.
  - **Timing.** RDTSC→CPUID→RDTSC pair compensation (bare-metal leaf cost instead of WHP exit latency, Ophion pattern) verified present, plus new per-handler CPUID exit-latency telemetry (logged every 1000 exits).
- **M0 milestone (spike) — full solution builds clean again.** The tree had drifted to a non-compiling state with **no vendored SDK header and a fabricated WHP API** (`WHvPartitionPropertyCodeSyscallExitBitmap`). M0 verified the real WHP semantics against SDK 10.0.26100 `WinHvPlatformDefs.h` and Microsoft docs, then fixed every defect: the fabricated syscall bitmap, a duplicated proxy-loading block in `src/engine/Main.cpp`, missing `<vector>` includes (`CpuidHandler.h`, `RdtscHandler.h`), unresolved export-ID names in `EngineExports.cpp`, `size_t→uint32_t` truncation warnings (`Snapshot.cpp`), a const-correctness SRWLOCK bug (`MsrHandler.h`), GCC-only `__attribute__((packed))` in `QemuTableGen.cpp` (now MSVC-compatible via `SYM_PACK_*` macros), and multiple targets missing from the build files (`QemuTableGen.cpp`, `Orchestrator.cpp`, `ProxyRenamer.cpp`, `ByovdDetect.cpp`, `KernelProxy.cpp`). All 21 targets build clean under `/W4 /WX`.
- **Real WHP properties identified for the M1 work** (they exist in the API and this codebase should use them, per master plan WS-1/WS-2/WS-10): `WHvPartitionPropertyCodeMsrActionList`, `WhvPartitionPropertyCodeUnimplementedMsrAction` (per-MSR RDMSR/WRMSR disposition), `WHvPartitionPropertyCodeProcessorPerfmonFeatures` (APERF/MPERF/fixed counters), `WHvPartitionPropertyCodeProcessorClockFrequency`, `WHvPartitionPropertyCodeInterruptClockFrequency`, `WHvPartitionPropertyCodeReferenceTime` (guest clocks), `WHvPartitionPropertyCodeCpuidResultList2`, `WHvPartitionPropertyCodeDisableSmt`, `WHvPartitionPropertyCodeProcessorFeatures`/`ProcessorFeaturesBanks`. `WHvGetPartitionProperty` does **not** support `CpuidExitList`/`CpuidResultList` (documented in MS docs) — the codebase correctly uses `WHvSetPartitionProperty` for those.

- **`ICpuBackend`/`WhpBackend` abstraction is now properly wired up.** `WhpBackend` has been refactored from a stub into a fully functional WHP lifecycle manager — partition creation, VCPU setup, EPT identity mapping, and syscall dispatch are all routed through it. The backend exposes a clean C-linkage interface that both the launcher and the engine call into, replacing the direct `Partition`/`VcpuManager` usage that previously lived in the engine alone. Shared state (the partition handle, VCPU array, lock, and backend config) is managed by `WhpBackend` itself, and all the original WHP modules (`Partition`, `VcpuManager`, `ExitDispatcher`, etc.) are accessible as before through the backend's exported pointers.
- **`IpcFilter` and `RegistryRedirection` are now fully wired into `ntdll_proxy`.** The proxy DLL's `dllmain.cpp` has been extended with sandbox-route entry points that call `EngineExports_ShouldBlockIpc` and `EngineExports_ShouldRedirectRegistry` before dispatching ALPC/pipe connections and registry reads. The sandbox-routing decision logic in `EngineExports` itself has also been added, completing the chain from proxy DLL → engine exports → sandbox module.
- **BYOVD (Bring Your Own Vulnerable Driver) module added.** `ByovdDriver` locates and uses a signed third-party driver to gain `\Device\PhysicalMemory`-style access from user mode, maps physical memory for hypervisor-level introspection, and unloads cleanly. **Enabled by default** (locked decision D4) — gated by a `[byovd]` config section, read-side only, no driver binaries bundled.
- **Xbox GDK proxy DLL added.** `xgameruntime_proxy/dllmain.cpp` shims `xboxgameruntime.dll` / `Microsoft.Gaming.XboxGameBarRT.dll` for titles running under the Xbox Game Pass / Microsoft Store runtime. Returns spoofed identity data via the same `EngineExports` HWID infrastructure.
- **Sandbox routing entry point fully implemented.** `EngineExports.cpp/.h` now exports `EngineExports_ShouldRedirectRegistry` and `EngineExports_ShouldBlockIpc` — called by `ntdll_proxy` — and `EngineExports_GetSpoofedIdentity` — called by `xgameruntime_proxy`. The HWID data, firmware tables, and sandbox decisions all live behind these three entry points.
- **CPUID leaf 0x1A (hybrid topology) handler added.** `SystemProfile` supports `[cpuid.0x1A]` config section for hybrid profile data. `HwDetect::ApplyFeatureMask` has an explicit case for leaf 0x1A (clears EBX/EDX on subleaf 0, subleaf 1 passthrough with masking). `CpuidHandler` serves leaf 0x1A with subleaf 0 (`nativeModelId`/`coreType`) and subleaf 1 (`coreCount`/`coreMask`) — returns zero for non-hybrid CPU profiles (Xeon, AMD, all existing defaults).
- **Handler serialization for Snapshot save/restore.** `CpuidHandler`, `RdtscHandler`, and `MsrHandler` now expose `Serialize()`/`Deserialize()` methods. `Snapshot::CreateInMemory()` and `Create()` call them in order (Cpuid → Rdtsc → Msr → EptExecHook), and `Snapshot::RestoreInMemory()`/`Restore()` deserialize in the same sequence. EPT memory regions are rebuilt on restore via `Partition::MapGpaRange()`.
- **VcpuManager save/restore checkpointing.** `VcpuManager::SaveCheckpoint()` and `RestoreCheckpoint()` serialize VCPU register state (46 registers via `WHvGetVirtualProcessorRegisters`/`WHvSetVirtualProcessorRegisters`) into a flat buffer under `KernelLock`. `Partition::SetVcpuCount()` tracks VCPU count for snapshot metadata. On engine shutdown, `Main.cpp` saves `checkpoint.snap` when snapshot is enabled.
- **`UnicornBackend` fully implemented with dynamic `unicorn.dll` loading.** All `ICpuBackend` stubs are now filled: `uc_open`/`uc_close` for engine lifecycle, `uc_emu_start` for execution, `uc_reg_read`/`uc_reg_write` for register access, `uc_mem_map_ptr`/`uc_mem_unmap` for memory mapping, `uc_mem_read`/`uc_mem_write` for memory access, and a `UC_HOOK_CODE` callback that detects `0F 05` SYSCALL instructions. The backend loads `unicorn.dll` at runtime via `LoadLibraryA` (no compile-time dependency) and resolves all symbols via `GetProcAddress`. A new `[backend] type = unicorn` config option selects it; the engine creates a `g_unicornBackend` instance and cleans it up on shutdown.
- **ConfigSnapshot (immutable config baking).** `ConfigSnapshot.h` defines the entire engine configuration as a single flat struct — CPU profile, timing, BIOS/SMBIOS, storage, GPU, network, sandbox, BYOVD, kernel proxy, memory, rename table, and feature flags. Populated once by the launcher at setup from `config.ini`, then baked into the target process at injection time. The INI file can be deleted at runtime with no effect.
- **Universal BYOVD auto-detection.** `ByovdDetect` scans 8 known vulnerable signed drivers (Intel GPU, ASUS GLCKIo, Razer RzDriver, MSI WinRing0, AORUS, EVGA, GMER, PhyMem) at runtime, tries each until one works, and falls back to admin `\\.\PhysicalMemory` if none are present. Capabilities are validated by probe IOCTLs. Supports physical memory R/W, kernel memory R/W, pool allocation, memory mapping, and SSDT hooks — all via IOCTL wrapper methods.
- **KernelProxy framework with SSDT + EPROCESS + LSTAR + IDT hooks.** `KernelProxy` writes kernel-mode stubs into non-paged pool via BYOVD physical memory. Deploys an EPROCESS sanitizer thread (hides from Dbgk, spoofs CreateTime, spoofs parent PID, clears PEB flags), an LSTAR/MSR change monitor (detects and restores anti-cheat LSTAR hooks), an IDT hook for syscall pre-filtering, and a driver list hider. Five kernel stub targets (`k_ntoskrnl`, `k_dxgkrnl`, `k_win32k`, `k_ndis`, `k_volmgr`) each contain initialization and spoof entry points for SSDT injection.
- **ProxyRenamer (random 8-hex-digit DLL naming).** Each run generates unique random names for all 15 proxy DLLs from a cryptographic seed (BCryptGenRandom). Rename table is baked into `ConfigSnapshot` and passed to the engine via shared memory. Engine loads proxies by their random names — no DLL name in the target process directory reveals the proxy's purpose. FNⅤ-1a hash used for integrity verification.
- **Orchestrator (8-phase launcher startup).** `Orchestrator` runs the full 8-phase boot sequence: Phase 0 (bake `ConfigSnapshot` from INI), Phase 1 (BYOVD auto-detect), Phase 2 (kernel proxy injection), Phase 3 (sandbox/VHDX setup), Phase 4 (WHP partition pre-creation), Phase 5 (proxy DLL rename), Phase 6 (engine + snapshot injection), Phase 7 (target resume). Each phase returns success/failure with error messages. Reverse-order shutdown for clean teardown.
- **QEMU firmware table generation (Tier B).** `QemuTableGen` generates complete ACPI (RSDP, RSDT, XSDT, FADT, FACS, DSDT, HPET, MCFG, DMAR) and SMBIOS (Type 0/1/4) tables from configuration. Tables are deployed into WHP partition GPA space at engine init. Always-on — no separate QEMU process needed. Configurable via `[qemu_tier_b]` section. The firmware region is built as a contiguous blob and identity-mapped via `Partition::MapGpaRange`.
- **Syscall interception mechanism (M0-corrected).** `Partition::SetupSyscallBitmap` referenced `WHvPartitionPropertyCodeSyscallExitBitmap` / `WHV_SYSCALL_EXIT_BITMAP` — **these do not exist in any shipped WinHvPlatform.h** (verified against SDK 10.0.26100 and the Microsoft docs; there is also no `WHvRunVpExitReasonX64Syscall` exit reason). The WHP API offers no per-syscall exit bitmap. Actual mechanism in use: LSTAR→HLT redirection (`SetupLstarMsrs`) traps **every** syscall as `WHvRunVpExitReasonX64Halt` → `HandleSyscallExit`, with selective interception available via EPT execute-access hooks on `0F 05` (`EptExecHook` / `SystemSpoofer::HandleEptSyscallIntercept`). The function was rewritten as an explicit documented no-op so the fabricated API can't come back.
- **Export Address Table replaced with function address table (sole named export).** `Engine_GetExport` is now the **only** named export from `engine.dll` — all 22 engine functions are resolved by integer ID via this single entry point. `#pragma comment(linker, "/EXPORT:RouteSyscall")` and all other per-function named exports have been removed. Proxy DLLs resolve every function via `ResolveEngineExport(FUNC_*)` using the shared `ProxyExportTable.h` helper instead of `GetProcAddress(hEngine, "FuncName")`. The table header (version + count + entries) is written to shared memory at engine init via `Engine_BuildExportTable`. `GetProcAddress` by name against engine.dll will only succeed for `Engine_GetExport` itself.
- **Windows Lite build script.** `scripts/build_minimal_win.ps1` creates a bootable VHDX with a stripped Windows installation — no Explorer, no DWM, no audio, no network stack, no Defender, no update service, no bloat. Target footprint: ~4GB disk, ~512MB-1GB RAM idle. Uses DISM for package/capability removal, offline registry tweaks, file bloat deletion, and service disabling. `scripts/create_winlite_vm.ps1` creates the corresponding isolated Hyper-V Gen-2 VM.
- **Firecracker and KasperskyHook research applied.** CPU template system and CPUID normalization patterns from Firecracker informed `SystemProfile` and `CpuidHandler` design. KasperskyHook's hypervisor detection via CPUID signatures and ExGetPreviousMode pattern matching informed kernel proxy countermeasure architecture.

**What's still genuinely incomplete:**

- **`config/config.example.ini`** was recently regenerated to match the current `ConfigParser` schema (an older version of this file used a different, incompatible key format and silently wouldn't have loaded). It should work as a starting point now, but it hasn't been validated against real captured hardware — treat the MSR block especially as a plausible placeholder rather than a verified dump.
- **A couple of the `KUSER_SHARED_DATA.ProcessorFeatures` byte layouts** (`KuserHook`/`KuserSync`) are best-effort — the writes no longer corrupt each other (they used to overlap), but getting bit-exact parity with a specific real CPU's feature byte pattern would need the layout re-derived from an actual hardware dump.
- **The engine loop still manages WHP directly via `Partition`/`VcpuManager` rather than through the `ICpuBackend` interface.** The `WhpBackend` and `UnicornBackend` classes are compiled and internally consistent, but the main execution loop hasn't been refactored to dispatch through `ICpuBackend` — so `UnicornBackend` can be used programmatically via its own API but isn't yet the primary execution engine. A `[backend] type=unicorn` config option selects it for code-level emulation alongside the existing WHP runtime.
- **CPUID leaf 0x1A (hybrid topology) returns zero for non-hybrid profiles** and configured `nativeModelId`/`coreType` for hybrid ones (i9-13900K profile). The `SystemProfile` loads hybrid data from `[cpuid.0x1A]` config section, `HwDetect::ApplyFeatureMask` handles leaf 0x1A masking, and `CpuidHandler` serves leaf 0x1A with subleaf 1 support.
- **Unified architecture is structurally complete, builds clean (M0), not yet integration-tested.** The `Orchestrator`, `ByovdDetect`, `KernelProxy`, `ProxyRenamer`, `QemuTableGen`, and `ConfigSnapshot` modules are each written and compilable — `Orchestrator.Run()` replaces the old direct inject/resume logic in `launcher/Main.cpp`, and all proxy DLLs that reference engine exports (`ntdll_proxy`, `wbem_proxy`) use `ResolveEngineExport(FUNC_*)` instead of `GetProcAddress`. QEMU Tier A (full Windows guest via WHPX) is documented and scripted (`scripts/create_winlite_vm.ps1`) but the VHDX needs to be built manually via `scripts/build_minimal_win.ps1`. Kernel proxy stubs (`k_ntoskrnl`, `k_dxgkrnl`, etc.) have shellcode placeholders — the actual injection and SSDT hook logic needs per-Windows-version syscall index maps (and per the master plan, kernel-proxy functionality beyond read-side BYOVD stays out of scope — this project is user-mode first).

---

## Related work

- **[Sogen](https://github.com/hedronium/Sogen)** — WHP+Unicorn+KVM CPU backend abstraction, LSTAR→HLT syscall interception, real system DLLs loaded in the guest, GDB stub, deterministic replay. Symbiote's overall approach follows Sogen's closely; see [Credits](#credits) for the file-level attribution.
- **[WinVisor](https://github.com/ionescu007/winvisor)** — process memory cloning directly into a WHP guest via identity-mapped EPT. `ProcessCloner` implements the same idea.
- **[Sandboxie](https://github.com/sandboxie-plus/Sandboxie)** — user-mode file/registry/IPC redirection. The isolation layer here follows the same patterns at the syscall-emulation level instead of a kernel driver.
- **[RedSand](https://github.com/redcode-labs/RedSand)** — `.wsb`-style profile presets for Windows Sandbox. Inspired the `--profile` system and `scripts/setup-dev.ps1`.
- **[negativespoofer](https://github.com/SamuelTulach/negativespoofer)** — EFI-level SMBIOS spoofing, adapted here to syscall/firmware-table interception instead.
- **[mutante](https://github.com/SamuelTulach/mutante)** — kernel-mode disk serial and S.M.A.R.T. spoofing, reimplemented at the IOCTL dispatch layer.
- **[MemoryGuard](https://github.com/SamuelTulach/MemoryGuard)** — PAGE_GUARD-based memory hiding, extended to syscall-level filtering.
- **[libkrun](https://github.com/containers/libkrun)** — TSC frequency detection and CPUID brand-string generation.
- **[DXVK](https://github.com/doitsujin/dxvk)** — the GPU passthrough layer forwards to DXVK where present.
- **[Unicorn Engine](https://github.com/unicorn-engine/unicorn)** — CPU emulation framework `UnicornBackend` is built against; see [Status](#status) for integration status.

### Credits

| Project | Author | What was adapted | Where |
|---|---|---|---|
| [Sogen](https://github.com/hedronium/Sogen) | hedronium | CPU backend abstraction, LSTAR→HLT interception, real-DLL guest approach, deterministic replay, DXVK GPU passthrough, MSR bitmap tuning | `ICpuBackend.h`, `WhpBackend.*`, `UnicornBackend.*`, `VcpuManager.*`, `ReplayLogger.*`, the 15 proxy DLLs, `Partition.*`, `DxvkIntegration.*` |
| [WinVisor](https://github.com/ionescu007/winvisor) | Alex Ionescu | Process memory cloning into a WHP guest via identity-mapped EPT | `ProcessCloner.*` |
| [Sandboxie](https://github.com/sandboxie-plus/Sandboxie) | sandboxie-plus | File/registry COW redirection, ALPC/pipe filtering, VHDX sandbox storage, WMI COM wrapping | `VirtualDisk.*`, `FileRedirection.*`, `RegistryRedirection.*`, `IpcFilter.*`, `SandboxFallthrough.*`, `ntdll_proxy/dllmain.cpp`, `wbem_proxy/dllmain.cpp` |
| [RedSand](https://github.com/redcode-labs/RedSand) | redcode-labs | `.ini` profile presets, dev-environment provisioning pattern | `profiles/*.ini`, `scripts/setup-dev.ps1` |
| [negativespoofer](https://github.com/SamuelTulach/negativespoofer) | Samuel Tulach | Firmware-level SMBIOS spoofing, adapted to syscall interception | `HwIdEmu.*`, `EngineExports.*`, `ntdll_proxy/dllmain.cpp` |
| [mutante](https://github.com/SamuelTulach/mutante) | Samuel Tulach | Disk serial / S.M.A.R.T. spoofing | `HwIdEmu.*` |
| [MemoryGuard](https://github.com/SamuelTulach/MemoryGuard) | Samuel Tulach | PAGE_GUARD memory hiding | `MemoryGuardEmu.*` |
| [libkrun](https://github.com/containers/libkrun) | containers | TSC frequency detection, CPUID brand-string generation | `TimingCoordinator.*`, `CpuidHandler.*` |
| [DXVK](https://github.com/doitsujin/dxvk) | doitsujin | DXVK DLL passthrough, Vulkan layer detection | `DxvkIntegration.*`, `GpuBridge.*` |
| [Unicorn Engine](https://github.com/unicorn-engine/unicorn) | unicorn-engine | Software CPU emulation, intended fallback backend | `UnicornBackend.*` |
| [kov.dev WHP research](https://kov.dev/) | kov | WHP performance tuning: MSR bitmap sizing, large-page mappings | `Partition.*` |
| [shimbox](https://github.com/notscimmy/shimbox) | notscimmy | BYOVD user-kernel shared-memory physical-mapping pattern, WHPX QEMU integration approach | `ByovdDriver.*`, `WhpBackend.*` |
| [Firecracker](https://github.com/firecracker-microvm/firecracker) | Amazon | CPU template system, CPUID normalization, MSR template approach, minimal device model | `CpuidHandler.*`, `SystemProfile.*`, architecture inspiration |
| [KasperskyHook](https://github.com/iilegacyyii/KasperskyHook) | iilegacyyii | Hypervisor detection via CPUID signatures, ExGetPreviousMode pattern matching, inter-hypervisor coordination | kernel proxy design, detection countermeasure patterns |

Every file that implements a technique from one of these projects has a `// Credits:` comment at the top pointing back to the source.

---

## License

Custom **Symbiote Fair Usage License**, see [LICENSE](LICENSE). Short version: use, copy, modify, and redistribute it freely for lawful purposes; don't use it to circumvent copy protection or violate a platform's terms of service; it's provided as-is with no warranty and the authors aren't liable for how it's used.
