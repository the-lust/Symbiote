# Symbiote — Hardware Fingerprint Analysis Techniques

How each fingerprint vector is observed and logged.

---

## 1. CPUID

### Observable Data
- **Leaf 0x0**: Max input value, vendor string
- **Leaf 0x1**: Processor signature, feature flags (hypervisor bit at ECX[31])
- **Leaf 0x40000000**: VMM presence
- **Leaves 0x80000002–4**: Processor brand string (48 bytes)
- **Leaf 0x80000001**: Extended feature flags

### Interception Mechanism
1. **WHP exit handler**: Configures CPUID exit handling via WHP partition. On each CPUID execution, the VCPU exits to user-space where engine.dll returns values from the configured profile.
2. **VEH fallback**: Scans target `.text` for `cpuid` instructions, overwrites with `UD2`. VEH handler catches the exception, runs CPUID, modifies results.
3. **Hypervisor leaf detection**: Leaves `0x40000000` and `0x40000001` are zeroed to observe detection behavior.
4. **Dynamic code**: CPUID from JIT/allocated memory uses guard-page VEH handler.

---

## 2. RDTSC / RDTSCP

### Observable Data
- RDTSC: Timestamp Counter (EDX:EAX)
- RDTSCP: Timestamp Counter + Processor ID (RCX)

### Interception Mechanism
1. **WHP exit handler**: RDTSC/RDTSCP exit handling configured on WHP partition.
2. **VEH fallback**: Target `.text` scanned for `rdtsc`/`rdtscp`, replaced with `UD2`.

---

## 3. MSR (Model-Specific Registers)

### Observable Data
- IA32_PLATFORM_ID (0x17)
- IA32_FEATURE_CONTROL (0x3A)
- IA32_TIME_STAMP_COUNTER (0x10)
- IA32_APIC_BASE (0x1B)
- VMX MSRs (0x480-0x48E)

### Interception Mechanism
WHP MSR exit handler returns configured values for known MSR indices.

---

## 4. KUSER_SHARED_DATA

Mapped at `0x7FFE0000` on x64 Windows. Contains system-wide shared data including tick count, interrupt time, system time, processor counts, and feature bitmaps.

### Interception Mechanism
1. **WHP EPT hook**: The KUSER GPA page is mapped to engine-controlled memory via EPT.
2. **VEH fallback**: Read-only shared memory overlay intercepts access attempts.

---

## 5. NtQuerySystemInformation

### Interception Mechanism
Syscall dispatcher intercepts specific information classes and returns configured values.

---

## 6. Registry

### Interception Mechanism
`NtOpenKey`/`NtOpenKeyEx` interceptors parse the requested registry path. Registry paths related to known hardware enumeration are intercepted.

---

## 7. WMI (Windows Management Instrumentation)

### Interception Mechanism
`wbem_proxy` DLL intercepts COM calls for `IWbemServices::ExecQuery` and `IWbemServices::ExecMethod`. Returns configured hardware identity values for classes: Win32_Processor, Win32_ComputerSystem, Win32_VideoController, Win32_NetworkAdapter, Win32_PhysicalMemory, Win32_BaseBoard, Win32_BIOS, Win32_DiskDrive, and sensor classes.

---

## 8. SMBIOS / DMI Tables

### Interception Mechanism
`NtQuerySystemInformation` is intercepted for firmware table queries (class 0x1D), returning `STATUS_INFO_LENGTH_MISMATCH`.

---

## 9. Timing Analysis

### Observable Data
- `QueryPerformanceCounter` / `QueryPerformanceFrequency`
- `GetTickCount64`
- `GetSystemTime`
- `GetSystemTimeAdjustment`

### Interception Mechanism
TimingEmu derives all values from a synthetic time base.

---

## 10. Thread / PEB Analysis

### Interception Mechanism
Process Environment Block (PEB) fields are managed through `ProcessEmu`. Thread enumeration queries are intercepted at the toolhelp32 and NtQuerySystemInformation level.

---

## 11. Syscall Interception (LSTAR→HLT)

When WHP is active, LSTAR MSR is redirected to a page containing only HLT instructions. On SYSCALL, the guest halts, causing a WHP exit. The dispatcher reads RAX (syscall number) and forwards to the appropriate handler or the host ntdll.

---

## 12. EPT-Based Execution Hooks

Selected pages have EXEC permission stripped from EPT entries. Execution attempts trigger a memory-access exit for inspection. After singlestep, EXEC is restored.

---

## Research Context

These techniques are documented for academic study of hardware fingerprinting mechanisms and hypervisor-based introspection.
