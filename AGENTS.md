# Genjutsu — Project Context

## Structure
```
genjutsu/
├── CMakeLists.txt           # Multi-arch build (MSVC x64/x86, MinGW)
├── CMakePresets.json        # 6 build presets
├── Makefile                 # MinGW fallback
├── .gitignore
├── LICENSE                  # MIT
├── README.md                # Project overview + build + usage
├── AGENTS.md                # This file
├── config/
│   ├── config.ini           # i9-10900K / RX 6800 XT spoof profile
│   └── config.example.ini   # Example config template
├── src/
│   ├── launcher/            # launcher.exe — CLI, process create, inject, init
│   ├── engine/              # engine.dll — WHP + VEH + IAT + SoGen
│   │   ├── whp/             # WHP partition, VCPUs, CPUID/RDTSC/MSR/EPT
│   │   ├── sogen/           # Syscall emulator (NtQuery*, NtOpen*, etc.)
│   │   ├── proxy/           # IAT patching, inline hooks, GpuBridge, SoGenBridge
│   │   ├── profile/         # CPU/GPU/Storage/Timing identity profiles
│   │   └── log/             # Logger subsystem
│   └── proxydlls/           # 13 proxy DLL shims (ntdll → ws2_32)
├── internal/                # Dev-only test harness (NOT shipped)
│   ├── poc/                 # poc_demo fingerprint test harness
│   └── tests/               # Unit tests (test_runner, test_target)
├── scripts/
│   └── build.bat            # Full build pipeline (clean → configure → build)
└── docs/
    ├── RESULTS.md           # Real vs spoofed comparison tables
    ├── TECHNIQUES.md        # Per-vector spoofing explainers
    └── ARCHITECTURE.md      # Research architecture doc
```

## Build Commands
- `cmake --preset msvc-x64 && cmake --build --preset msvc-x64` (x64 Release)
- `cmake --preset msvc-x64-debug && cmake --build --preset msvc-x64-debug` (x64 Debug)
- `scripts\build.bat` or `scripts\build.bat debug`
- Output: `build/msvc/x64/bin/Release/` (engine.dll, launcher.exe, 13 proxy DLLs)

## Key Architecture
- **No kernel drivers.** All Ring 3.
- **WHP API** does hardware virtualization without kernel code (degrades to VEH if unavailable).
- **SoGen** provides syscall handlers for 50+ ntdll syscalls.
- **13 proxy DLLs** intercept IAT-bound API calls and route to engine or fallthrough.
- **CodePatcher** (VEH-based) patches CPUID/RDTSC/RDTSCP in target `.text` via INT3.
- **MsrPatcher** patches RDMSR/WRMSR instructions in target code.
- **KUSER_SHARED_DATA** managed with EPT hooks (WHP sidecar) + KuserHook fallback (VEH).
- **IAT scanning** limited to main EXE `.text` section, capped at 200 patches.

## Debug Logging
- `launcher --debug --target target.exe` enables per-event tracing to stdout + `emu.log`
- `Engine_SetDebug()` is called before `Engine_Init()` to capture full initialization trace
- Log categories: INFO, WARN, ERR, WHP, SOGEN, PROXY, EPT, CPUID, TIMING

## Verified Tools
- Coreinfo64: CPUID 000A0655, brand "Intel i9-10900K" ✅
- Procmon64: No leaks ✅
- WinObj64: No handle leaks ✅
