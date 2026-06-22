#include "KuserSync.h"
#include "Partition.h"
#include "ConfigParser.h"
#include <cstring>

KuserSync::KuserSync(Logger* logger, Partition* partition)
    : m_logger(logger), m_partition(partition),
      m_syncThread(nullptr), m_stopEvent(nullptr), m_running(false),
      m_spoofedKuser(nullptr),
      m_systemTimeOffset(0), m_interruptTimeOffset(0), m_utcBias(-300)
{
}

KuserSync::~KuserSync()
{
    StopSyncThread();
    if (m_spoofedKuser) {
        if (m_partition) {
            m_partition->UnmapGpaRange(KUSER_GPA, KUSER_PAGE_SIZE);
        }
        VirtualFree(m_spoofedKuser, 0, MEM_RELEASE);
    }
}

bool KuserSync::Initialize()
{
    m_spoofedKuser = VirtualAlloc(NULL, KUSER_PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!m_spoofedKuser) {
        m_logger->Trace(LOG_ERROR, "KuserSync: failed to allocate KUSER buffer");
        return false;
    }

    if (m_partition) {
        WHV_MAP_GPA_RANGE_FLAGS flags = (WHV_MAP_GPA_RANGE_FLAGS)(WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite);
        if (!m_partition->MapGpaRange(m_spoofedKuser, KUSER_GPA, KUSER_PAGE_SIZE, flags)) {
            m_logger->Trace(LOG_ERROR, "KuserSync: failed to map KUSER buffer at GPA 0x%llX", KUSER_GPA);
            VirtualFree(m_spoofedKuser, 0, MEM_RELEASE);
            m_spoofedKuser = nullptr;
            return false;
        }
    }

    ApplyStaticSpoofs();
    SyncTimeFields();

    m_logger->Trace(LOG_EPT, "KUSER buffer allocated at %p and mapped at GPA 0x%llX", m_spoofedKuser, KUSER_GPA);
    return true;
}

bool KuserSync::Initialize(ConfigParser* config)
{
    if (!Initialize()) return false;

    if (config) {
        m_systemTimeOffset = static_cast<int64_t>(config->GetUint64("kuser", "system_time_offset", 0));
        m_interruptTimeOffset = static_cast<int64_t>(config->GetUint64("kuser", "interrupt_time_offset", 0));
        m_utcBias = config->GetInt("kuser", "utc_bias", -300);
        m_logger->Trace(LOG_EPT, "KUSER config: sysTimeOff=%lld intTimeOff=%lld utcBias=%d",
            m_systemTimeOffset, m_interruptTimeOffset, m_utcBias);
    }

    return true;
}

void KuserSync::ApplyStaticSpoofs()
{
    uint8_t* kuser = (uint8_t*)m_spoofedKuser;

    // tick count multiplier + initial tick
    *(uint64_t*)(kuser + 0x000) = 0x0FA0000000000000ULL;

    // NtMajorVersion (0x58 = Win 10 20H2), NtMinorVerion, BuildNumber, CSDverion (0x260-0x264)
    kuser[0x260] = 0x58;
    *(uint64_t*)(kuser + 0x261) = 0x0100000001000066ULL;
    kuser[0x264] = 0x01;
    // SuiteMask, ProductType, reserved
    *(uint64_t*)(kuser + 0x268) = 0x0A00090001ULL;
    kuser[0x26c] = 0x0A;
    kuser[0x26e] = 0x00;
    // ProcessorFeatures - broad feature set claim
    *(uint64_t*)(kuser + 0x270) = 0x00ULL;
    *(uint64_t*)(kuser + 0x272) = 0x010100000000ULL;
    *(uint64_t*)(kuser + 0x273) = 0x0100000101000000ULL;
    *(uint64_t*)(kuser + 0x281) = 0x0100000100000101ULL;
    *(uint64_t*)(kuser + 0x282) = 0x0101000001000001ULL;
    *(uint64_t*)(kuser + 0x283) = 0x0101010000010000ULL;
    *(uint32_t*)(kuser + 0x288) = 0x01010101;
    // more processor features
    *(uint32_t*)(kuser + 0x290) = 0x01010101;
    *(uint64_t*)(kuser + 0x294) = 0x0101010101010101ULL;
    *(uint64_t*)(kuser + 0x29C) = 0x0101010101010101ULL;
    *(uint64_t*)(kuser + 0x2A4) = 0x0001010101010101ULL;
    *(uint32_t*)(kuser + 0x2AC) = 0x01010101;
    // reserved/extension bits
    *(uint64_t*)(kuser + 0x2B0) = 0x0000000000000000ULL;
    *(uint64_t*)(kuser + 0x2B8) = 0x0000000000000000ULL;
    *(uint64_t*)(kuser + 0x2C0) = 0x0000000000000000ULL;
    *(uint64_t*)(kuser + 0x2C8) = 0x0000000000000000ULL;

    // SuiteMask @ 0x2D0 (ULONG) — HyperKD token profile low 32 bits
    *(uint32_t*)(kuser + 0x2D0) = 0x00000110;
    // KdDebuggerEnabled @ 0x2D4 — bit 1 = KdDebuggerNotPresent
    kuser[0x2D4] = 0x02;
    kuser[0x2D5] = 0x01;
    // ProductType: Workstation (0x2E8)
    kuser[0x2E8] = 0x01;
    // SystemExpirationDate: none (0x2F0)
    *(uint64_t*)(kuser + 0x2f0) = 0x0ULL;
    *(uint64_t*)(kuser + 0x2f4) = 0x0ULL;
    // DualFact and Debug flags (0x300-0x310)
    *(uint32_t*)(kuser + 0x300) = 0x00000000;
    *(uint32_t*)(kuser + 0x308) = 0x00000000;
    *(uint32_t*)(kuser + 0x310) = 0x00000000;

    // ReservedForFlags and alignment (0x378-0x390)
    *(uint64_t*)(kuser + 0x378) = 0x0100000000ULL;
    *(uint64_t*)(kuser + 0x380) = 0x0000000000000000ULL;
    *(uint64_t*)(kuser + 0x388) = 0x0000000000000000ULL;
    *(uint64_t*)(kuser + 0x390) = 0x0000000000000000ULL;
    // Thermal and idle info (0x398-0x3C0)
    *(uint64_t*)(kuser + 0x398) = 0x0000000000000000ULL;
    *(uint64_t*)(kuser + 0x3A0) = 0x00000000ULL;
    *(uint64_t*)(kuser + 0x3B0) = 0x0000000000000000ULL;
    // DeepSleepData and IdleInfo (0x3C0-0x3F0)
    *(uint64_t*)(kuser + 0x3C0) = 0x83000100000010ULL;
    *(uint64_t*)(kuser + 0x3C8) = 0x0000000000000000ULL;
    // Cookie and cycle fields (0x3D8-0x3F0)
    *(uint64_t*)(kuser + 0x3D8) = 0x0000000000000000ULL;
    *(uint64_t*)(kuser + 0x3E0) = 0x0000000000000000ULL;
    *(uint64_t*)(kuser + 0x3E8) = 0x0000000000000000ULL;
    *(uint64_t*)(kuser + 0x3F0) = 0x0000000000000000ULL;
    *(uint64_t*)(kuser + 0x3F8) = 0x0000000000000000ULL;

    // printf("kuser static spoofs applied\n");
    m_logger->Trace(LOG_EPT, "KUSER static spoofs applied (full page)");
}

void KuserSync::SyncTimeFields()
{
    if (!m_spoofedKuser) return;

    uint8_t* realKuser = (uint8_t*)0x7FFE0000;
    uint8_t* spoofed = (uint8_t*)m_spoofedKuser;

    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);

    uint64_t tickCount = qpc.QuadPart / 10000;
    uint64_t interruptTime = qpc.QuadPart + m_interruptTimeOffset;
    uint64_t sysTime;
    GetSystemTimeAsFileTime((LPFILETIME)&sysTime);
    sysTime += m_systemTimeOffset;

    // SystemTime (0x318 = low, 0x320 = high)
    *(volatile uint64_t*)(spoofed + 0x318) = sysTime;
    *(volatile uint64_t*)(spoofed + 0x320) = sysTime >> 32;

    // InterruptTime (0x328 = low, 0x330 = high)
    *(volatile uint64_t*)(spoofed + 0x328) = interruptTime;
    *(volatile uint64_t*)(spoofed + 0x330) = interruptTime >> 32;

    // InterruptTime bias copy (0x338 = low, 0x340 = high)
    *(volatile uint64_t*)(spoofed + 0x338) = interruptTime;
    *(volatile uint64_t*)(spoofed + 0x340) = interruptTime >> 32;

    // TickCount (0x348 = low, 0x34C = high, 0x350 = high alternate)
    *(volatile uint32_t*)(spoofed + 0x348) = (uint32_t)(tickCount & 0xFFFFFFFF);
    *(volatile uint32_t*)(spoofed + 0x34C) = (uint32_t)(tickCount >> 32);
    *(volatile uint32_t*)(spoofed + 0x350) = (uint32_t)(tickCount >> 32);

    // TickCount bias and time zone bias fields
    *(volatile uint32_t*)(spoofed + 0x354) = *(volatile uint32_t*)(realKuser + 0x354);
    *(volatile uint32_t*)(spoofed + 0x358) = m_utcBias;
    *(volatile uint32_t*)(spoofed + 0x35C) = *(volatile uint32_t*)(realKuser + 0x35C);
    *(volatile uint32_t*)(spoofed + 0x360) = *(volatile uint32_t*)(realKuser + 0x360);

    // QPC value
    *(volatile uint64_t*)(spoofed + 0x370) = qpc.QuadPart;

    // ACPI thermal zone and power management info - passthrough from host
    *(volatile uint32_t*)(spoofed + 0x3A0) = *(volatile uint32_t*)(realKuser + 0x3A0);
    *(volatile uint32_t*)(spoofed + 0x3A8) = *(volatile uint32_t*)(realKuser + 0x3A8);
    *(volatile uint32_t*)(spoofed + 0x3AC) = *(volatile uint32_t*)(realKuser + 0x3AC);
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
