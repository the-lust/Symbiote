# Symbiote Phase 9 Changelog

## Completed: 2026-07-16 (Build Fixes — 2026-07-16)

### Build Fixes (all targets now compile cleanly on MSVC x64)
- **TimingCoordinator.h**: Changed `class TimingCoordinator` → `struct TimingCoordinator` to match forward declarations in CpuidHandler.h/RdtscHandler.h (C4099)
- **DeviceIoEmu.cpp**: Replaced `__declspec(naked)` + `__asm { }` trampoline with `extern "C"` function matching NtDeviceIoControlFile signature (MSVC x64 does not support inline asm)
- **DeviceIoEmu.h**: Moved `InstallHook()`, `RemoveHook()`, `HandleGetPartitionProperty()` to public so the C-linkage trampoline can call them
- **MinimalKernel.h**: Moved `GetDeviceIoEmu()` from private to public section
- **Main.cpp**: Added `#include "emu/DeviceIoEmu.h"` for full type definition
- **SyscallDispatch.cpp**: Replaced `&HandleNtQueryVirtualMemory` bound-member-function address with `GetModuleHandleW(L"engine.dll")` (C2276/C2660)
- **ProcessEmu.cpp**: Fixed truncation `0x190` → `0x19` (C4305 uint8_t overflow)
- **AcpiTimerHandler.h**: Removed `static` from `GetSyntheticPmTimer()`/`GetSyntheticHpetCounter()` (C2597 — cannot access non-static members from static methods)
- **EptSplitView.cpp**: Removed unused `GetOptimalPageSize` variable (C4189)
- **ThreadHider.cpp**: Added `(void)` casts for unreferenced parameters in `HandleSystemProcessInformation` (C4100)
- **EptExecHook.h/.cpp**: Added `Serialize()`, `Deserialize()`, `HandleSingleStepComplete()`, `HandleExecFault()` — stubs called by `Snapshot` and `VcpuManager`
- **EptExecHook.cpp**: Implemented `Serialize()`/`Deserialize()` for hook-state snapshot; `HandleSingleStepComplete()` re-applies EPT execute-disable; `HandleExecFault()` fires callback + temporarily restores EXEC
- **CpuidHandler.cpp**: Added `(void)subleaf;` for unreferenced lambda capture parameter (C4100)
- **wbem_proxy/dllmain.cpp**: Fixed `ExecMethodAsync` signature (missing `IWbemClassObject* pInParams` — C3668/C2065); fixed `AdapterRAM()` return value 10GB → 2GB (C4305 uint32_t truncation)
- **CMakeLists.txt**: Added `TimingCoordinator.cpp` to ENGINE_SOURCES; added `winmm.lib` for `timeGetTime()`
- **Makefile**: Brought in sync with CMakeLists.txt — added all Phase 9/B source files (TimingCoordinator, SystemSpoofer, SyscallDispatch, EptExecHook, EptSplitView, AcpiTimerHandler, EptPageProtect, VeSimulation, ConsistencyVerifier, Snapshot, GuestPageTable, WatchdogTracker, Canary, KernelLock, DeviceIoEmu, ThreadHider, TimingProfile, CaptureLogger, DxvkIntegration)

### A1: Comprehensive CPUID Pre-Population
- **Files**: `CpuidHandler.cpp`, `Partition.cpp`
- All 512+ CPUID leaves (0x00-0xFF, 0x80000000-0x800000FF, 0x40000000-0x400000FF) pre-populated in WHP result list
- Eliminates VM-exits for unlisted leaves → Denuvo cannot measure RDTSC→CPUID→RDTSC delta
- Feature masking applied to all leaves

### A2: Enhanced RDTSC Timing Compensation
- **Files**: `RdtscHandler.cpp`, `RdtscHandler.h`
- CounterUpdater background thread advances synthetic TSC at configured frequency
- RDTSC handlers use synthetic counter instead of real TSC + offset
- Per-vendor noise model (Intel: mean=40, amp=20; AMD: mean=80, amp=40)
- Expanded CplLeafCost table (11→26 leaves)

### A3: NtDeviceIoControlFile Hook
- **Files**: `DeviceIoEmu.h`, `DeviceIoEmu.cpp` (NEW)
- 12-byte inline hook on ntdll!NtDeviceIoControlFile
- WHP IOCTL interception (GetPartitionProperty, RunVirtualProcessor, etc.)
- Partition property spoofing (processor count → 2)

### A4: Expanded WMI Coverage
- **File**: `wbem_proxy/dllmain.cpp`
- 8 new classes: Win32_VideoController, Win32_NetworkAdapter, Win32_PhysicalMemory,
  Win32_USBController, CIM_Sensor, Win32_TemperatureProbe, Win32_Fan, Win32_VoltageProbe
- ~45 new property handlers

### A5: Expanded SMBIOS Tables
- **File**: `ProcessEmu.cpp`
- 10 new SMBIOS types: Type 7 (L1/L2/L3 Cache), Type 17 (Memory Device),
  Type 19 (Memory Array Mapped Address), Type 21 (Trackpoint), Type 22 (Battery),
  Type 11 (OEM Strings), Type 13 (BIOS Language)
- Buffer expanded from 0x800 to 0x1000 bytes

### A6: Expanded Registry VM Artifact Blocking
- **File**: `RegistryEmu.cpp`
- 18 detection patterns (was 5): Hyper-V artifacts, BIOS registry paths, service entries

### A7: ACPI PM Timer / HPET MMIO Trapping
- **Files**: `AcpiTimerHandler.h`, `AcpiTimerHandler.cpp` (NEW)
- Synthetic ACPI PM timer (port 0x608, 3.579545 MHz, 24-bit)
- Synthetic HPET counter (~10MHz)

### A8: Thread Hiding
- **Files**: `ThreadHider.h`, `ThreadHider.cpp` (NEW)
- Hide engine threads from toolhelp API enumeration

### A9: EPT Split-View Performance
- **File**: `EptSplitView.cpp`
- View generation tracking (skip redundant WHvMapGpaRange)
- 2MB large page support
- ReadHiddenMemory/WriteHiddenMemory direct access
- ProtectMemoryRange (RX-only EPT)

### A10: Anti-Memory-Scanning for INT3
- **File**: `SystemSpoofer.cpp`
- INT3 camouflage (multi-byte NOP replacement)
- ApplyCamouflage/RestorePatches toggle

### A11: Enhanced TimingCoordinator
- **File**: `TimingCoordinator.cpp`
- JITTER_REALISTIC strategy with per-CPU profiles (i9/i7/i5/Xeon/Ryzen)
- ACPI PM timer and HPET cross-correlation
- Real-hardware drift model with rare spikes

### Build System
- **File**: `CMakeLists.txt`
- Added DeviceIoEmu.cpp, AcpiTimerHandler.cpp, ThreadHider.cpp

### Configuration
- **File**: `config/config.ini`
- Added ACPI timer, CounterUpdater, anti-scan, thread hider, device IO sections

### Next Phase (Phase B)
- Nested type-2 hypervisor (modified WinVisor as L1)
- Full CPUID ECX[31] control at L1
- EPT control with #VE support
- WHvGetPartitionProperty interception at L1
- Proper RDTSC scaling at L1
