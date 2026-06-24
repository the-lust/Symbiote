# Symbiote — Spoofing Techniques Reference

How each fingerprint vector works, why protection systems use it, and how Symbiote intercepts them from Ring 3.

---

## 1. CPUID

### What it reveals
- **Leaf 0x0**: Max input value, vendor string (`GenuineIntel`, `AuthenticAMD`)
- **Leaf 0x1**: Processor signature (family/model/stepping), feature flags (hypervisor bit at ECX[31])
- **Leaf 0x40000000**: VMM presence — returns `"Microsoft Hv"` under Hyper-V, `0x0` on bare metal
- **Leaf 0x40000001**: Hyper-V feature flags
- **Leaves 0x80000002–4**: Processor brand string (48 bytes)
- **Leaf 0x80000001**: Extended feature flags (SVM on AMD, etc.)

### How its used for fingerprinting
Protection systems call CPUID with multiple leafs to build a hardware signature. The presense of a hypervisor leaf (`0x40000000`) is a red flag for VM detection. Brand string and signature identifys the specific CPU model.

### How Symbiote spoofs it
1. **WHP exit handler** (when available): Configures CPUID exit handling on the WHP parition. On every CPUID execution, the VCPU exits to user-space where engine.dll returns spoofed registers from the profile.
2. **CodePatcher (VEH fallback)**: Scans the target `.text` section for `cpuid` instructions (opcode `0F A2`), overwrites them with `UD2` (`0F 0B`). When the target executs the `UD2`, a VEH handler catches the exception, runs the original CPUID instruction, modifys the result registers, and resumes execution.
3. **Hypervisor leaf hiding**: Leaves `0x40000000` and `0x40000001` are explicitly zeroed.
4. **AllocTracker full emulation** (Phase 6): When CPUID executes from JIT/allocated memory, the guard-page VEH handler now runs `__cpuidex` directly on the fault, applies spoofing to `RAX/RBX/RCX/RDX` in the CONTEXT record, and advances RIP — no UD2 patching needed.
5. **Brand string leaves** (Phase 3): Leaves `0x80000002-0x80000004` return config-driven brand string (default `Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz`). Enhanced mode allows an alternative brand string when the handshake protocol activates.
6. **Per-process CPUD**: Via MagicCpuid's `MAGIC_REGISTER_PID`, CpuidHandler only applies spoofing when `GetCurrentProcessId()` matches the registered target PID. All other processes inside the WHP partition get passthrough CPUID.

---

## 2. RDTSC / RDTSCP

### What it reveals
- **RDTSC**: Reads the timestamp counter (processor cycle counter)
- **RDTSCP**: Atomic read of TSC + processor ID
- **TSC deltas** around CPUID: Hypervisors typically cause measurable latency when CPUID triggers a VM exit

### How it's used for fingerprinting
Protection systems measure the delta of RDTSC calls around CPUID. A high delta (>1000 cycles) suggests a VM exit occured. TSC monotonicity checks detect if values are fabricated (not monotonicaly increasing).

### How Symbiote spoofs it
1. **WHP exit handler**: Handles RDTSC/RDTSCP exits, returns spoofed TSC values from `TimingProfile` with configurable frequency and noise.
2. **CodePatcher (VEH fallback)**: Patches `rdtsc` (`0F 31`) and `rdtscp` (`0F 01 F9`) instructions with `UD2`. VEH handler returns consistent monotonic TSC values.
3. **TSC frequency**: Configurable in `config.ini` — default `3.696 GHz` for i9-10900K.
4. **Delta masking**: TSC increments by a small amount around patched CPUID instructions to avoid detection by delta-based heuristics.
5. **TimingCoordinator**: Tracks consecutive RDTSC→CPUID→RDTSC patterns across the CpuidHandler and RdtscHandler. When detected, applies time delta normalization so inter-instruction timings appear consistent with bare-metal execution. Three jitter strategies available: uniform (0-500µs delay for CPUID, 0-200µs for RDTSC), constant (fixed configurable delay), and linear (base + LCG-scattered offset).

---

## 3. MSR (Model-Specific Registers)

### What it reveals
- **IA32_PLATFORM_ID** (`0x17`): Platform processor model
- **IA32_FEATURE_CONTROL** (`0x3A`): VMX enable status
- **IA32_MISC_ENABLE** (`0x1A0`): Turbo boost, thermal monitor
- **MSR_IA32_TSC** (`0x10`): TSC value
- Other MSRs reveal cache info, microcode version, thermal status

### How it's used for fingerprinting
VMX enable bit in `IA32_FEATURE_CONTROL` reveals if virtualization is active. Some MSRs have expected values on real hardware that differ under emulation.

### How Symbiote spoofs it
1. **WHP MsrHandler**: If WHP partition is available, MSR access exits are handled and spoofed values returned.
2. **MsrPatcher (VEH fallback)**: Scans target `.text` for `rdmsr`/`wrmsr` instructions, patches them with `UD2`. VEH handler emulates the instruction with spoofed MSR values.
3. **Note**: RDMSR/WRMSR are kernel-mode instructions on x64 Windows. If the target code runs at Ring 3, a kernel-mode MSR access indicates something suspicious already.

---

## 4. KUSER_SHARED_DATA

### What it reveals
The shared page at `0x7FFE0000` (readable from user mode) contains:
- `NtBuildNumber` + version info
- `KdDebuggerEnabled` / `KdDebuggerNotPresent`
- `SystemTime`, `InterruptTime`, `TickCount`
- `QPC` value
- `ProcessorFeatures` bitmask
- `SuiteMask`, `ProductType`
- Various kernel-exposed debug flags

### How it's used for fingerprinting
Protection systems directly read bytes from `0x7FFE0000` to check for:
- Kernel debugger presence (`KdDebuggerEnabled` byte)
- System time consistency (compare with other time sources)
- Processor feature bitmask consistency (cross-check with CPUID)

### How Symbiote spoofs it
1. **EPT hook (WHP)**: Maps a custom physical page at the same GPA as KUSER_SHARED_DATA. When the target reads from `0x7FFE0000`, it hits our spoofed page.
2. **KuserHook (VEH fallback)**: Creates a shared memory region mapped to a spoofed KUSER page. Memory access violations are caught by VEH and redirected to the spoofed page.
3. **Note**: The real KUSER page at `0x7FFE0000` is owned by the kernel and cannot be directly rewritten from user mode.

---

## 5. System Calls (NtQuerySystemInformation / NtQueryInformationProcess)

### What they reveal
- **NtQuerySystemInformation**
  - Class `0x05` (SystemProcessInformation): Process/thread enumeration
  - Class `0x0B` (SystemModuleInformation): Loaded kernel modules
  - Class `0x1E` (SystemKernelDebuggerInformation): KdDebugger state
  - Class `0x23` (SystemCodeIntegrityInformation): DSE status
  - Class `0x67` (SystemCodeIntegrityPolicy): CI policy flags
  - Class `0xB6` (SystemHypervisorInfo): Hyper-V presence
  - Many more
- **NtQueryInformationProcess**
  - Class `0x07` (ProcessDebugPort): Debugger attached?
  - Class `0x1E` (ProcessDebugObjectHandle): Debug object present?
  - Class `0x1F` (ProcessDebugFlags): Being debugged?

### How it's used for fingerprinting
These are the primary APIs for process/system introspection. Protection systems enumerate processes, check for debuggers, inspect kernel module load state, and verify code integrity flags.

### How Symbiote spoofs it
1. **InlineHook**: 5-byte `JMP` rel32 hook at the start of `ntdll.dll!NtQuerySystemInformation` and `NtQueryInformationProcess`. The hook redirects to MinimalKernel.
2. **MinimalKernel**: Maintains a spoofed virtual process list (25 entries), returns empty module list, hides kernel debugger, disables DSE, zeroes debug object handles, and masks hypervisor info.
3. **Fallthrough**: For non-sensitive classes, the real syscall is dispatched.

---

## 6. Registry (Processor Brand, Hardware Info)

### What it reveals
- `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0\ProcessorNameString`
- `HKLM\HARDWARE\DESCRIPTION\System\BIOS`
- `HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum`
- Various OEM/hardware-specific keys

### How it's used for fingerprinting
Protection systems read registry keys that expose processor name, BIOS version, disk model, and other hardware identifiers. These are often cross-referenced with CPUID and WMI values.

### How Symbiote spoofs it
1. **advapi32_proxy**: Intercepts `RegOpenKeyExW`, `RegQueryValueExW`, `RegCloseKey`. For known sensitive keys (processor name, hardware description), returns spoofed values.
2. **ntdll_proxy**: Intercepts low-level `NtOpenKey`, `NtQueryValueKey` for targets that bypass `advapi32`.
3. **kernel32_proxy**: `GetComputerNameW`, `CreateFileW` for volume queries.

---

## 7. WMI (Windows Management Instrumentation)

### What it reveals
- **Win32_Processor**: Name, number of cores/logical processors, max clock speed, processor ID, architecture, manufacturer, stepping, socket designation
- **Win32_VideoController**: GPU name, vendor, driver version, VRAM size
- **Win32_BIOS**: BIOS version, vendor, release date
- **Win32_DiskDrive**: Model, size, serial number, interface type
- **Win32_ComputerSystem**: Manufacturer, model, system type, total physical memory
- **Win32_BaseBoard**: Motherboard manufacturer, product, serial

### How it's used for fingerprinting
WMI is the gold standard for hardware fingerprinting because it returns rich, structured data from multiple hardware providers.

### How Symbiote spoofs it
1. **wbem_proxy.dll**: A full COM shim that implements:
   - `IWbemLocator` (1 method: `ConnectServer`)
   - `IWbemServices` (6 methods: `ExecQuery`, `ExecMethod`, etc.)
   - `IEnumWbemClassObject` (3 methods: `Next`, `Reset`, `Skip`)
   - `IWbemClassObject` (27 methods: `Get`, `Put`, `GetNames`, etc.)
2. **`ExecQuery` interception**: When the target queries `SELECT * FROM Win32_Processor`, the proxy intercepts the request and returns a spoofed `IWbemClassObject` with 12 custom properties.
3. **Fallthrough**: Unrecognized WMI queries pass through to the real WMI service.

---

## 8. PEB / TEB

### What it reveals
- **PEB+0x02**: BeingDebugged flag
- **PEB+0x0BC**: LDR structure (loaded modules, base addresses)
- **PEB+0x118**: ProcessParameters (command line, image path)
- **PEB+0x130**: NtGlobalFlag (heap flags when debugger present)

### How it's used for fingerprinting
Direct PEB reads are fast and don't require syscalls. Protection systems check BeingDebugged, NtGlobalFlag, and LDR module lists from the PEB.

### How Symbiote spoofs it
1. **MinimalKernel ProcessEmu**: Maintains a virtual PEB structure with clean debug flags.
2. **KUSER_SHARED_DATA masking**: Some PEB-adjacent state is also exposed via KUSER.
3. **Note**: PEB is per-process and relatively simple to clean. Most protection focuses on cross-layer consistency instead.

---

## 9. Timing Analysis (QPC, GetTickCount)

### What it reveals
- **QueryPerformanceCounter**: High-resolution system time
- **GetTickCount**: System uptime in milliseconds
- **timeGetTime**: System time
- **RDTSC deltas**: Execution time of sensitive code paths

### How it's used for fingerprinting
Protection systems measure execution time of functions that should be fast on real hardware. If a function (like CPUID) takes suspiciously long, it suggests a VM exit occurred. QPC values should be consistent with CPUID TSC values.

### How Symbiote spoofs it
1. **TimingEmu**: Returns consistent timing values aligned with the spoofed TSC frequency.
2. **MinimalKernel fallthrough**: Non-sensitive timing calls go to the real system.
3. **Cross-layer consistency**: Spoofed TSC values are designed to be consistent with QPC and GetTickCount.

---

## 10–16. Extended Proxy DLLs

These intercept additional IAT-bound API calls:

| Proxy DLL | APIs Intercepted | Detection Vector |
|-----------|-----------------|------------------|
| **ws2_32_proxy** | `socket`, `connect`, `send`, `recv`, `bind`, `listen`, `accept`, `gethostname`, `ioctlsocket`, `WSASocketW`, `WSAConnect` | Network behavior analysis |
| **dnsapi_proxy** | `DnsQuery_A`, `DnsQuery_W`, `DnsQuery_UTF8`, `DnsRecordListFree`, `DnsFlushResolverCache` | DNS query pattern analysis |
| **iphlpapi_proxy** | `GetAdaptersInfo`, `GetAdaptersAddresses`, `GetIfTable`, `GetIpNetTable`, `GetNetworkParams`, `GetUniDirectionalAdapterInfo`, `NotifyAddrChange`, `NotifyRouteChange`, `CancelMibChangeNotify2` | Network adapter enumeration |
| **winhttp_proxy** | `WinHttpOpen`, `WinHttpConnect`, `WinHttpOpenRequest`, `WinHttpSendRequest`, `WinHttpReceiveResponse`, `WinHttpQueryHeaders`, `WinHttpReadData`, `WinHttpCloseHandle`, `WinHttpSetOption`, `WinHttpSetTimeouts`, `WinHttpCrackUrl` | HTTP traffic shaping |
| **crypt32_proxy** | `CertOpenSystemStoreW`, `CertEnumCertificatesInStore`, `CertFindCertificateInStore`, `CertGetNameStringW`, `CertCloseStore`, `CertFreeCertificateContext`, `CertDuplicateCertificateContext`, `CryptAcquireContextW`, `CryptReleaseContext`, `CryptGenKey`, `CryptExportKey`, `CryptImportKey`, `CryptDecrypt`, `CryptEncrypt`, `CryptHashData`, `CryptCreateHash`, `CryptDestroyHash`, `CryptDestroyKey`, `CryptGetUserKey`, `CryptSignHashW`, `CryptVerifySignatureW`, `CertCreateCertificateContext` | Crypto provider enumeration |
| **secur32_proxy** | `InitializeSecurityContextW`, `AcceptSecurityContext`, `CompleteAuthToken`, `DeleteSecurityContext`, `FreeContextBuffer`, `ImpersonateSecurityContext`, `QueryContextAttributesW`, `QuerySecurityPackageInfoW`, `RevertSecurityContext`, `FreeCredentialsHandle`, `AcquireCredentialsHandleW`, `EnumerateSecurityPackagesW` | Security context analysis |
| **wtsapi32_proxy** | `WTSQuerySessionInformationW`, `WTSFreeMemory`, `WTSEnumerateSessionsW`, `WTSCloseServer`, `WTSOpenServerW` | Session/terminal info enumeration |

---

## Degradation Modes

When WHP is unavailable (`WHvCreatePartition` fails), the engine degrades gracefully:

| Feature | WHP Mode | VEH + IAT Mode |
|---------|----------|----------------|
| CPUID spoofing | WHP exit handler | CodePatcher (VEH) |
| RDTSC spoofing | WHP exit handler | CodePatcher (VEH) |
| MSR spoofing | WHP MsrHandler | MsrPatcher (VEH) |
| KUSER spoofing | EPT page remap | KuserHook (VEH + shared memory) |
| IAT hooks | Proxy DLLs | Proxy DLLs (same) |
| Inline hooks | MinimalKernel bridge | MinimalKernel bridge (same) |
|

In degraded mode, all vectors remain spoofable, but VEH patching is less stealthy than WHP exit handling because it modifies `.text` sections with `UD2` instructions.

---

## 11. Magic CPUID Handshake Protocol

### What it enables
- **Target-to-engine coordination**: The target process can register its PID, announce its syscall handler base, toggle enhanced spoofing profiles, and set up a shared memory GPA — all via CPUID magic leaves.
- **Per-process tracking**: Once a target registers via `MAGIC_REGISTER_PID`, CpuidHandler only applies spoofing when the current PID matches — all other processes inside the WHP partition get passthrough CPUID.

### Handshake Leaves

| Leaf | Name | Purpose | Input | Output |
|------|------|---------|-------|--------|
| `0x69696969` / subleaf `0x1337` | HELLO/ACK | Engine presence check | — | `"HaHoul"` magic |
| `0x33690001` | GET_GPA | Query engine GPA | — | Current GPA value |
| `0x33690002` | SET_GPA | Set engine GPA | RAX=GPA | — |
| `0x41414141` | QUIT | Stop VCPU | — | Quit acknowledged |
| `0x1337` | REGISTER_PID | Register target PID | RDX=PID | Registered PID |
| `0x336933` | REGISTER_SYSCALL | Register syscall handler | RCX=addr | Registered address |
| `0x336934` | GET_SYSCALL_HANDLER | Query registered handler | — | Registered address |
| `0xDEADBEEF` / subleaf toggle | ENHANCED_MODE | Enable enhanced spoofing | subleaf=1 ON, 0 OFF | Current state |
| `0x33690003` | SET_SHM | Register shared memory GPA | RAX=GPA | — |
| `0x33690004` | GET_SHM | Query shared memory GPA | — | Registered GPA |

### How Symbiote implements it
1. **MagicCpuid**: Handles all magic leaves in `HandleMagicCpuid()` before regular CpuidHandler dispatch.
2. **Per-process check**: CpuidHandler calls `MagicCpuid::HasTargetPid()` and `GetTargetPid()` — if a target is registered, only spoofs when `GetCurrentProcessId()` matches.
3. **Enhanced mode**: When `MAGIC_ENHANCED_MODE` is toggled, CpuidHandler uses the enhanced brand string (from config or hardcoded override) instead of the default.
4. **Shared memory GPA**: The target can SET_SHM to announce a GPA for shared handshake state, and GET_SHM to retrieve whatever GPA the engine set up (e.g., the Canary page).

---

## 12. Memory Scanner Canary

### What it detects
- **Memory scanning**: Anti-cheat or anti-debugging code that walks memory regions looking for hooked pages, guard pages, or other protection artifacts.
- **Handshake page access**: When the target (or an injected third party) accesses the canary page, the VEH callback fires and logs the access as a potential scan event.

### How Symbiote implements it
1. **Canary class**: Allocates a 4KB page with `VirtualAlloc`, keeps it in RW state with no guard set initially.
2. **VEH handler**: On `STATUS_ACCESS_VIOLATION` or `EXCEPTION_GUARD_PAGE` at the canary address, logs the fault and sets a `scanned` flag in the `CanaryHandshake` struct. Removes the guard and resumes execution.
3. **CanaryHandshake layout**:
   - Offset `0x00`: `magic` (0x584D5942)
   - Offset `0x04`: `flags` (bit 0 = scanned)
   - Offset `0x08`: `handshakeGpa` (shared with MagicCpuid)
   - Offset `0x10`: `targetPid`
   - Offset `0x18`: 4080 bytes reserved
4. **Integration with MagicCpuid**: The canary page address can be shared with the target via `MAGIC_SET_SHM` / `MAGIC_GET_SHM`, allowing the target to read handshake state (e.g., whether a scan was detected, current PID tracking state).
