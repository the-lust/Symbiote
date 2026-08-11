#include "KuserSync.h"
#include "Partition.h"
#include "ConfigParser.h"
#include "RdtscHandler.h"
#include "../kernel/VirtualClock.h"
#include <cstring>

KuserSync::KuserSync(Logger* logger, Partition* partition)
    : m_logger(logger), m_partition(partition), m_rdtscHandler(nullptr),
      m_syncThread(nullptr), m_stopEvent(nullptr), m_running(false),
      m_gpaMapped(false), m_spoofedKuser(nullptr),
      m_systemTimeOffset(0), m_interruptTimeOffset(0), m_utcBias(-300)
{
}

KuserSync::~KuserSync()
{
    StopSyncThread();
    if (m_spoofedKuser) {
        if (m_partition && m_gpaMapped) {
            m_partition->UnmapGpaRange(KUSER_GPA, KUSER_PAGE_SIZE);
            m_gpaMapped = false;
        }
        VirtualFree(m_spoofedKuser, 0, MEM_RELEASE);
        m_spoofedKuser = nullptr;
    }
}

bool KuserSync::Initialize()
{
    if (m_spoofedKuser) return true;

    // Fail-loud layout gate: pre-19041 KUSER layouts are NOT byte-certified
    // in this codebase (see KuserLayout.h). Spoofing them would be fabrication.
    if (!KuserIsModernLayout(m_buildNumber)) {
        m_logger->Trace(LOG_ERROR,
            "KuserSync: KUSER layout for build %u (< 19041) is not byte-certified; "
            "refusing to spoof (WS-9 matrix)",
            m_buildNumber);
        return false;
    }

    m_spoofedKuser = VirtualAlloc(NULL, KUSER_PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!m_spoofedKuser) {
        m_logger->Trace(LOG_ERROR, "KuserSync: failed to allocate KUSER buffer");
        return false;
    }

    // Zero-rule base: the page starts fully zeroed; only TIP-config fields and
    // math-module values are ever written. Nothing is copied from the host.
    memset(m_spoofedKuser, 0, KUSER_PAGE_SIZE);

    if (m_partition) {
        WHV_MAP_GPA_RANGE_FLAGS flags = (WHV_MAP_GPA_RANGE_FLAGS)(WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite);
        if (!m_partition->MapGpaRange(m_spoofedKuser, KUSER_GPA, KUSER_PAGE_SIZE, flags)) {
            m_logger->Trace(LOG_ERROR, "KuserSync: failed to map KUSER buffer at GPA 0x%llX", KUSER_GPA);
            VirtualFree(m_spoofedKuser, 0, MEM_RELEASE);
            m_spoofedKuser = nullptr;
            return false;
        }
        m_gpaMapped = true;
    }

    ApplyStaticSpoofs();
    SyncTimeFields();

    m_logger->Trace(LOG_EPT, "KUSER buffer allocated at %p and mapped at GPA 0x%llX "
        "(identity-mapped guest PTEs: KUSER VA == GPA)", m_spoofedKuser, KUSER_GPA);
    return true;
}

bool KuserSync::Initialize(ConfigParser* config)
{
    if (config) {
        LoadConfig(config);
    }
    return Initialize();
}

bool KuserSync::ReapplyGpaMapping()
{
    if (!m_spoofedKuser || !m_partition) return m_gpaMapped;

    WHV_MAP_GPA_RANGE_FLAGS flags = (WHV_MAP_GPA_RANGE_FLAGS)(WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite);
    if (!m_partition->MapGpaRange(m_spoofedKuser, KUSER_GPA, KUSER_PAGE_SIZE, flags)) {
        m_logger->Trace(LOG_ERROR, "KuserSync: ReapplyGpaMapping failed at GPA 0x%llX", KUSER_GPA);
        return false;
    }
    m_gpaMapped = true;
    m_logger->Trace(LOG_EPT, "KuserSync: spoof mapping re-asserted at GPA 0x%llX", KUSER_GPA);
    return true;
}

void KuserSync::LoadConfig(ConfigParser* config)
{
    m_systemTimeOffset = static_cast<int64_t>(config->GetUint64("kuser", "system_time_offset", 0));
    m_interruptTimeOffset = static_cast<int64_t>(config->GetUint64("kuser", "interrupt_time_offset", 0));
    m_utcBias = config->GetInt("kuser", "utc_bias", -300);
    m_ntMajorVersion = (uint32_t)config->GetInt("kuser", "nt_major_version", 10);
    m_ntMinorVersion = (uint32_t)config->GetInt("kuser", "nt_minor_version", 0);
    m_buildNumber = (uint32_t)config->GetInt("kuser", "build_number", 19045);
    m_productType = (uint32_t)config->GetInt("kuser", "product_type", 1);
    m_productTypeIsValid = (uint8_t)config->GetInt("kuser", "product_type_is_valid", 1);
    m_nativeProcessorArchitecture = (uint16_t)config->GetInt("kuser", "native_processor_architecture", 9);
    m_suiteMask = (uint32_t)config->GetInt("kuser", "suite_mask", 0x0110);
    m_activeProcessorCount = (uint32_t)config->GetInt("kuser", "active_processor_count", 4);
    m_activeGroupCount = (uint32_t)config->GetInt("kuser", "active_group_count", 1);
    m_numberOfPhysicalPages = config->GetUint64("kuser", "number_of_physical_pages", 0x1FA054);
    m_qpcFrequency = config->GetUint64("kuser", "qpc_frequency", config->GetUint64("timing", "qpc_frequency", 10000000));
    m_tscFrequency = config->GetUint64("kuser", "tsc_frequency", config->GetUint64("timing", "tsc_frequency", 1995375200));
    m_systemTimeAnchor = config->GetUint64("kuser", "system_time_anchor", 0);
    m_mitigationPolicies = (uint8_t)config->GetInt("kuser", "mitigation_policies", 0x0A);
    m_cyclesPerYield = (uint16_t)config->GetInt("kuser", "cycles_per_yield", 9);
    m_sharedDataFlags = (uint32_t)config->GetInt("kuser", "shared_data_flags", 0);

    // Optional byte-exact ProcessorFeatures blob (hex, e.g. 64 bytes captured
    // from the donor machine). Absent -> all zeros (zero-rule).
    std::string blob = config->GetString("kuser", "processor_features", "");
    memset(m_processorFeatures, 0, sizeof(m_processorFeatures));
    if (!blob.empty()) {
        size_t nibbles = 0;
        for (size_t i = 0; i < blob.size(); i++) {
            char c = blob[i];
            int v = -1;
            if (c >= '0' && c <= '9') v = c - '0';
            else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
            else continue;
            if (nibbles < sizeof(m_processorFeatures) * 2) {
                if ((nibbles & 1) == 0) m_processorFeatures[nibbles / 2] = (uint8_t)(v << 4);
                else m_processorFeatures[nibbles / 2] |= (uint8_t)v;
                nibbles++;
            }
        }
        m_logger->Trace(LOG_EPT, "KUSER: processor_features blob applied (%zu nibbles)", nibbles);
    }

    m_logger->Trace(LOG_EPT,
        "KUSER config: build=%u ver=%u.%u product=%u arch=%u suite=0x%04X pages=0x%llX "
        "procCount=%u group=%u qpc=%llu tsc=%llu utcBias=%d anchor=0x%llX sysOff=%lld intOff=%lld",
        m_buildNumber, m_ntMajorVersion, m_ntMinorVersion, m_productType,
        m_nativeProcessorArchitecture, m_suiteMask, m_numberOfPhysicalPages,
        m_activeProcessorCount, m_activeGroupCount, m_qpcFrequency, m_tscFrequency,
        m_utcBias, m_systemTimeAnchor, m_systemTimeOffset, m_interruptTimeOffset);

    // Wire the shared clock so NtQuerySystemTime and KUSER.SystemTime agree.
    VirtualClock::Get().Configure(m_qpcFrequency, m_tscFrequency);
    VirtualClock::Get().SetTscSource(m_rdtscHandler);
    VirtualClock::Get().SetSystemTimeOffset(m_systemTimeOffset);
    if (m_systemTimeAnchor != 0) {
        VirtualClock::Get().SetSystemTimeAnchor(m_systemTimeAnchor);
    }
}

void KuserSync::SetKSystemTime(KSYSTEM_TIME_X64* dst, uint64_t value)
{
    // KSYSTEM_TIME write pattern: LowPart + High1Time, then High2Time mirrors
    // High1Time so readers doing the tear check see a stable 64-bit value.
    dst->LowPart = (uint32_t)(value & 0xFFFFFFFF);
    dst->High1Time = (int32_t)(value >> 32);
    dst->High2Time = dst->High1Time;
}

void KuserSync::ApplyStaticSpoofs()
{
    if (!m_spoofedKuser) return;

    KUSER_SHARED_DATA_X64* k = (KUSER_SHARED_DATA_X64*)m_spoofedKuser;

    // ---- Identity fields (TIP-config) ----
    k->NtBuildNumber = m_buildNumber;
    k->NtProductType = m_productType;
    k->ProductTypeIsValid = m_productTypeIsValid;
    k->NativeProcessorArchitecture = m_nativeProcessorArchitecture;
    k->NtMajorVersion = m_ntMajorVersion;
    k->NtMinorVersion = m_ntMinorVersion;
    memcpy(k->ProcessorFeatures, m_processorFeatures, sizeof(k->ProcessorFeatures));
    k->SuiteMask = m_suiteMask;
    k->NumberOfPhysicalPages = (uint32_t)m_numberOfPhysicalPages;
    k->FullNumberOfPhysicalPages = m_numberOfPhysicalPages;
    k->ActiveProcessorCount = m_activeProcessorCount;
    k->ActiveGroupCount = (uint8_t)m_activeGroupCount;
    k->UnparkedProcessorCount = (uint16_t)m_activeProcessorCount;
    k->MitigationPolicies = m_mitigationPolicies;
    k->CyclesPerYield = m_cyclesPerYield;
    k->SharedDataFlags = m_sharedDataFlags;

    // ---- Environment/math fields (real-validated constants) ----
    // 0x8664 = IMAGE_FILE_MACHINE_AMD64 for both bounds (real machines: 0x8664/0x8664).
    k->ImageNumberLow = 0x8664;
    k->ImageNumberHigh = 0x8664;
    k->LargePageMinimum = 0x200000; // 2 MB
    k->QpcFrequency = (int64_t)m_qpcFrequency;
    // Real Win10/Win11 with QPC=10MHz: 0x0FA00000 (262144000). Scaled by the
    // configured QPC frequency, validated against the live machine.
    k->TickCountMultiplier = (uint32_t)((m_qpcFrequency * (1ULL << 32)) / 163840000ULL);
    k->QpcSystemTimeIncrement = 0x8000000000000000ULL; // matches 10MHz-QPC systems
    k->QpcInterruptTimeIncrement = 0x8000000000000000ULL;
    k->QpcSystemTimeIncrementShift = 1;
    k->QpcInterruptTimeIncrementShift = 1;

    // ---- Debugger/VM surface: explicitly clean ----
    k->KdDebuggerEnabled = 0;        // no kernel debugger
    k->SystemCall = 0;               // AMD64: nonzero = altered syscall view -> MUST be 0
    k->SafeBootMode = 0;
    k->VirtualizationFlags = 0;

    // ---- Zero-rule: everything not config-verified stays 0 (page was zeroed) ----
    // Includes: TimeZoneBias fields (driven in SyncTimeFields), Cookie,
    // ConsoleSessionForegroundProcessId, InterruptTimeBias, QpcBias,
    // TimeZoneBiasEffectiveStart/End, BootId, LastSystemRITEventTickCount,
    // EnclaveFeatureMask, TelemetryCoverageRound, UserModeGlobalLogger,
    // TimeSlip, SystemExpirationDate, ActiveConsoleId, DismountCount,
    // ComPlusPackage, RNGSeedVersion, TimeZoneBiasStamp, TestRetInstruction.

    // TimeZoneBias (config utc_bias, 100ns units) — KSYSTEM_TIME triplet.
    SetKSystemTime(&k->TimeZoneBias, (uint64_t)(int64_t)m_utcBias * 10000000LL);

    m_logger->Trace(LOG_EPT, "KUSER static spoofs applied (layout-typed, zero-rule base)");
}

void KuserSync::SyncTimeFields()
{
    if (!m_spoofedKuser) return;

    VirtualClock& clock = VirtualClock::Get();

    KUSER_SHARED_DATA_X64* k = (KUSER_SHARED_DATA_X64*)m_spoofedKuser;

    uint64_t vqpc = clock.VirtualQpc100ns();
    uint64_t sysTime = clock.SystemTime();
    uint64_t intTime = vqpc + (uint64_t)(int64_t)m_interruptTimeOffset;
    uint64_t tickCount = clock.TickCountQuad();

    SetKSystemTime(&k->SystemTime, sysTime);
    SetKSystemTime(&k->InterruptTime, intTime);

    k->TickCountQuad = tickCount;
    k->TickCountHigh2Time = (int32_t)(tickCount >> 32);
    k->TickCountLowDeprecated = (uint32_t)tickCount;

    k->TimeUpdateLock = clock.TimeUpdateLock();
    k->BaselineSystemTimeQpc = vqpc;
    k->BaselineInterruptTimeQpc = vqpc;

    // Keep ActiveProcessorCount authoritative from TIP config every sync
    // (some kernel paths rewrite it on CPU hot-add in real systems).
    k->ActiveProcessorCount = m_activeProcessorCount;
    k->UnparkedProcessorCount = (uint16_t)m_activeProcessorCount;
}

bool KuserSync::StartSyncThread()
{
    if (m_running) return true;

    m_stopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!m_stopEvent) return false;

    m_syncThread = CreateThread(NULL, 0, SyncThreadProc, this, 0, NULL);
    if (!m_syncThread) {
        CloseHandle(m_stopEvent);
        return false;
    }

    m_running = true;
    m_logger->Trace(LOG_EPT, "KUSER sync thread started (1ms interval)");
    return true;
}

void KuserSync::StopSyncThread()
{
    if (m_running) {
        SetEvent(m_stopEvent);
        if (m_syncThread) {
            WaitForSingleObject(m_syncThread, 1000);
            CloseHandle(m_syncThread);
        }
        if (m_stopEvent) CloseHandle(m_stopEvent);
        m_running = false;
    }
}

DWORD WINAPI KuserSync::SyncThreadProc(LPVOID lpParam)
{
    KuserSync* self = (KuserSync*)lpParam;

    while (true) {
        DWORD waitResult = WaitForSingleObject(self->m_stopEvent, 1);
        if (waitResult == WAIT_OBJECT_0) break;

        self->SyncTimeFields();
    }

    return 0;
}