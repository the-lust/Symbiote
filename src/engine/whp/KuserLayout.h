#pragma once
#include <windows.h>
#include <cstdint>
#include <cstddef>

// ---------------------------------------------------------------------------
// KUSER_SHARED_DATA byte-exact layout (x64, Windows 10 20H1+ / Windows 11,
// NT build 19041+).
//
// The modern layout is derived from the shared NT headers (phnt ntexapi.h,
// SDK 26100) and was validated FIELD-BY-FIELD against a live page dump on
// Windows 11 build 26200: every offset asserted below matched the real page
// byte-for-byte (NtBuildNumber=0x6658 @0x260, NtMajorVersion=10 @0x26C,
// SuiteMask=0x0110 @0x2D0, QpcFrequency=10000000 @0x300, TickCountQuad @0x320,
// ActiveProcessorCount @0x3C0, ProcessorFeatures @0x274 ...).
//
// Historical note: builds before 19041 (1809/1903/1909 = 17763/18362/18363)
// used an OLDER layout that placed NtMajorVersion (BYTE) @0x260, SuiteMask
// @0x26C, ProcessorFeatures @0x270 and NumberOfPhysicalPages @0x2D8. The
// engine does NOT byte-certify that layout (WS-9 matrix); spoofing it would
// violate the zero-rule. KuserSync refuses to initialize for build < 19041
// (fail-loud).
// ---------------------------------------------------------------------------

#define KUSER_VA        0x7FFE0000ULL
#define KUSER_PAGE_SIZE 0x1000
// Guest page tables are identity-mapped (guest VA -> GPA = VA), so the KUSER
// page's GPA IS its VA (0x7FFE0000) — the spoof buffer maps at KUSER_GPA.
#define KUSER_GPA       KUSER_VA

// KSYSTEM_TIME is a 12-byte race-tolerant triplet (LowPart, High1Time,
// High2Time). Writers set High2Time = High1Time last; readers verify the
// 64-bit value via LowPart|High1Time<<32 and re-read if High1 != High2.
struct KSYSTEM_TIME_X64 {
    uint32_t LowPart;
    int32_t  High1Time;
    int32_t  High2Time;
};

struct KUSER_SHARED_DATA_X64 {
    /* 0x000 */ uint32_t TickCountLowDeprecated;
    /* 0x004 */ uint32_t TickCountMultiplier;
    /* 0x008 */ KSYSTEM_TIME_X64 InterruptTime;
    /* 0x014 */ KSYSTEM_TIME_X64 SystemTime;
    /* 0x020 */ KSYSTEM_TIME_X64 TimeZoneBias;
    /* 0x02C */ uint16_t ImageNumberLow;
    /* 0x02E */ uint16_t ImageNumberHigh;
    /* 0x030 */ wchar_t NtSystemRoot[260];
    /* 0x238 */ uint32_t MaxStackTraceDepth;
    /* 0x23C */ uint32_t CryptoExponent;
    /* 0x240 */ uint32_t TimeZoneId;
    /* 0x244 */ uint32_t LargePageMinimum;
    /* 0x248 */ uint32_t AitSamplingValue;
    /* 0x24C */ uint32_t AppCompatFlag;
    /* 0x250 */ uint64_t RNGSeedVersion;
    /* 0x258 */ uint32_t GlobalValidationRunlevel;
    /* 0x25C */ int32_t  TimeZoneBiasStamp;
    /* 0x260 */ uint32_t NtBuildNumber;
    /* 0x264 */ uint32_t NtProductType;
    /* 0x268 */ uint8_t  ProductTypeIsValid;
    /* 0x269 */ uint8_t  Reserved0;
    /* 0x26A */ uint16_t NativeProcessorArchitecture;
    /* 0x26C */ uint32_t NtMajorVersion;
    /* 0x270 */ uint32_t NtMinorVersion;
    /* 0x274 */ uint8_t  ProcessorFeatures[64];
    /* 0x2B4 */ uint32_t MaximumUserModeAddressDeprecated;
    /* 0x2B8 */ uint32_t SystemRangeStartDeprecated;
    /* 0x2BC */ uint32_t TimeSlip;
    /* 0x2C0 */ uint32_t AlternativeArchitecture;
    /* 0x2C4 */ uint32_t BootId;
    /* 0x2C8 */ int64_t  SystemExpirationDate;
    /* 0x2D0 */ uint32_t SuiteMask;
    /* 0x2D4 */ uint8_t  KdDebuggerEnabled;
    /* 0x2D5 */ uint8_t  MitigationPolicies;
    /* 0x2D6 */ uint16_t CyclesPerYield;
    /* 0x2D8 */ uint32_t ActiveConsoleId;
    /* 0x2DC */ uint32_t DismountCount;
    /* 0x2E0 */ uint32_t ComPlusPackage;
    /* 0x2E4 */ uint32_t LastSystemRITEventTickCount;
    /* 0x2E8 */ uint32_t NumberOfPhysicalPages;
    /* 0x2EC */ uint8_t  SafeBootMode;
    /* 0x2ED */ uint8_t  VirtualizationFlags;
    /* 0x2EE */ uint8_t  Reserved12[2];
    /* 0x2F0 */ uint32_t SharedDataFlags;
    /* 0x2F4 */ uint32_t DataFlagsPad;
    /* 0x2F8 */ uint64_t TestRetInstruction;
    /* 0x300 */ int64_t  QpcFrequency;
    /* 0x308 */ uint32_t SystemCall;
    /* 0x30C */ uint32_t Reserved2;
    /* 0x310 */ uint64_t FullNumberOfPhysicalPages;
    /* 0x318 */ uint64_t SystemCallPad;
    /* 0x320 */ uint64_t TickCountQuad;   // also KSYSTEM_TIME TickCount (LowPart|High1<<32)
    /* 0x328 */ int32_t  TickCountHigh2Time;
    /* 0x32C */ uint32_t TickCountPad;
    /* 0x330 */ uint32_t Cookie;
    /* 0x334 */ uint32_t CookiePad;
    /* 0x338 */ int64_t  ConsoleSessionForegroundProcessId;
    /* 0x340 */ uint64_t TimeUpdateLock;
    /* 0x348 */ uint64_t BaselineSystemTimeQpc;
    /* 0x350 */ uint64_t BaselineInterruptTimeQpc;
    /* 0x358 */ uint64_t QpcSystemTimeIncrement;
    /* 0x360 */ uint64_t QpcInterruptTimeIncrement;
    /* 0x368 */ uint8_t  QpcSystemTimeIncrementShift;
    /* 0x369 */ uint8_t  QpcInterruptTimeIncrementShift;
    /* 0x36A */ uint16_t UnparkedProcessorCount;
    /* 0x36C */ uint32_t EnclaveFeatureMask[4];
    /* 0x37C */ uint32_t TelemetryCoverageRound;
    /* 0x380 */ uint16_t UserModeGlobalLogger[16];
    /* 0x3A0 */ uint32_t ImageFileExecutionOptions;
    /* 0x3A4 */ uint32_t LangGenerationCount;
    /* 0x3A8 */ uint64_t Reserved4;
    /* 0x3B0 */ uint64_t InterruptTimeBias;
    /* 0x3B8 */ uint64_t QpcBias;
    /* 0x3C0 */ uint32_t ActiveProcessorCount;
    /* 0x3C4 */ uint8_t  ActiveGroupCount;
    /* 0x3C5 */ uint8_t  Reserved9;
    /* 0x3C6 */ uint16_t QpcData;         // low byte = QpcBypassEnabled flags (phnt)
    /* 0x3C8 */ int64_t  TimeZoneBiasEffectiveStart;
    /* 0x3D0 */ int64_t  TimeZoneBiasEffectiveEnd;
    /* 0x3D8 */ uint8_t  XState[0x338];      // zero-rule zone (never populated)
};

// Compile-time byte-exact certification of every offset the engine writes.
#define KUSER_ASSERT(field, off) \
    static_assert(offsetof(KUSER_SHARED_DATA_X64, field) == off, \
        "KUSER_SHARED_DATA." #field " offset mismatch (expected 0x" #off ")")

KUSER_ASSERT(TickCountLowDeprecated, 0x000);
KUSER_ASSERT(TickCountMultiplier, 0x004);
KUSER_ASSERT(InterruptTime, 0x008);
KUSER_ASSERT(SystemTime, 0x014);
KUSER_ASSERT(TimeZoneBias, 0x020);
KUSER_ASSERT(ImageNumberLow, 0x02C);
KUSER_ASSERT(ImageNumberHigh, 0x02E);
KUSER_ASSERT(NtSystemRoot, 0x030);
KUSER_ASSERT(MaxStackTraceDepth, 0x238);
KUSER_ASSERT(RNGSeedVersion, 0x250);
KUSER_ASSERT(NtBuildNumber, 0x260);
KUSER_ASSERT(NtProductType, 0x264);
KUSER_ASSERT(ProductTypeIsValid, 0x268);
KUSER_ASSERT(NativeProcessorArchitecture, 0x26A);
KUSER_ASSERT(NtMajorVersion, 0x26C);
KUSER_ASSERT(NtMinorVersion, 0x270);
KUSER_ASSERT(ProcessorFeatures, 0x274);
KUSER_ASSERT(SystemExpirationDate, 0x2C8);
KUSER_ASSERT(SuiteMask, 0x2D0);
KUSER_ASSERT(KdDebuggerEnabled, 0x2D4);
KUSER_ASSERT(MitigationPolicies, 0x2D5);
KUSER_ASSERT(CyclesPerYield, 0x2D6);
KUSER_ASSERT(NumberOfPhysicalPages, 0x2E8);
KUSER_ASSERT(SharedDataFlags, 0x2F0);
KUSER_ASSERT(QpcFrequency, 0x300);
KUSER_ASSERT(SystemCall, 0x308);
KUSER_ASSERT(FullNumberOfPhysicalPages, 0x310);
KUSER_ASSERT(TickCountQuad, 0x320);
KUSER_ASSERT(TickCountHigh2Time, 0x328);
KUSER_ASSERT(Cookie, 0x330);
KUSER_ASSERT(ConsoleSessionForegroundProcessId, 0x338);
KUSER_ASSERT(TimeUpdateLock, 0x340);
KUSER_ASSERT(BaselineSystemTimeQpc, 0x348);
KUSER_ASSERT(BaselineInterruptTimeQpc, 0x350);
KUSER_ASSERT(QpcSystemTimeIncrement, 0x358);
KUSER_ASSERT(QpcInterruptTimeIncrement, 0x360);
KUSER_ASSERT(QpcSystemTimeIncrementShift, 0x368);
KUSER_ASSERT(QpcInterruptTimeIncrementShift, 0x369);
KUSER_ASSERT(UnparkedProcessorCount, 0x36A);
KUSER_ASSERT(EnclaveFeatureMask, 0x36C);
KUSER_ASSERT(InterruptTimeBias, 0x3B0);
KUSER_ASSERT(QpcBias, 0x3B8);
KUSER_ASSERT(ActiveProcessorCount, 0x3C0);
KUSER_ASSERT(ActiveGroupCount, 0x3C4);
KUSER_ASSERT(QpcData, 0x3C6);
KUSER_ASSERT(TimeZoneBiasEffectiveStart, 0x3C8);
KUSER_ASSERT(TimeZoneBiasEffectiveEnd, 0x3D0);

#undef KUSER_ASSERT

// Layout selector: modern = build 19041+ (validated). Older layouts are not
// byte-certified in this codebase and the engine refuses to spoof them.
inline bool KuserIsModernLayout(uint32_t build)
{
    return build >= 19041;
}