# Symbiote Phase 9 Changelog

## Completed: 2026-07-16

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
