#pragma once
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <intrin.h>

// Structured query capture logger.
// Writes tab-separated capture.log with every hardware/software query.
// Format (one line per event):
//   VECTOR<TAB>timestamp<TAB>tid<TAB>callerRip<TAB>field1<TAB>field2<...>
// Vectors: CPUID, RDTSC, RDTSCP, MSR_READ, MSR_WRITE, KUSER, SYSCALL, REGISTRY,
//          FILE, PROCESS, ALLOC, GUARD_PAGE, DNS, NETWORK, CRYPTO, GPU, TIMING

class CaptureLogger {
public:
    CaptureLogger()
        : m_file(nullptr), m_startTick(0)
    {
        QueryPerformanceFrequency(&m_qpf);
        QueryPerformanceCounter(&m_qpcStart);
        m_startTick = GetTickCount64();
    }

    ~CaptureLogger()
    {
        Close();
    }

    bool Open(const wchar_t* logPath)
    {
        if (m_file) return true;
        errno_t e = _wfopen_s(&m_file, logPath, L"a, ccs=UTF-8");
        if (e != 0 || !m_file) return false;
        // header
        fprintf(m_file, "# Symbiote Capture Log\n");
        fprintf(m_file, "# VECTOR\\ttimestamp_ms\\ttid\\tcallerRip\\tfields...\n");
        fflush(m_file);
        return true;
    }

    void Close()
    {
        if (m_file) {
            fclose(m_file);
            m_file = nullptr;
        }
    }

    // Capture a CPUID event
    void CaptureCpuid(uint32_t leaf, uint32_t subleaf, uint64_t callerRip,
                      uint32_t eax, uint32_t ebx, uint32_t ecx, uint32_t edx)
    {
        Write("CPUID", callerRip, "%08X\t%08X\t%08X\t%08X\t%08X\t%08X",
              leaf, subleaf, eax, ebx, ecx, edx);
    }

    // Capture an RDTSC/RDTSCP event
    void CaptureRdtsc(const char* type, uint64_t callerRip, uint64_t tscValue)
    {
        Write(type, callerRip, "%016llX", tscValue);
    }

    // Capture an MSR read/write
    void CaptureMsr(const char* type, uint64_t callerRip,
                    uint32_t msr, uint64_t value)
    {
        Write(type, callerRip, "%08X\t%016llX", msr, value);
    }

    // Capture KUSER_SHARED_DATA access
    void CaptureKuser(uint64_t callerRip, uint32_t offset, uint32_t size, uint64_t value)
    {
        Write("KUSER", callerRip, "%04X\t%u\t%016llX", offset, size, value);
    }

    // Capture NtQuerySystemInformation
    void CaptureSysInfo(uint64_t callerRip, uint32_t infoClass, uint32_t bufSize, uint32_t status)
    {
        Write("SYSCALL", callerRip, "NtQuerySystemInformation\t%u\t%u\t%08X",
              infoClass, bufSize, status);
    }

    // Capture NtQueryInformationProcess
    void CaptureProcessInfo(uint64_t callerRip, uint32_t infoClass, uint32_t status)
    {
        Write("SYSCALL", callerRip, "NtQueryInformationProcess\t%u\t%08X",
              infoClass, status);
    }

    // Capture registry query
    void CaptureRegistry(uint64_t callerRip, const char* path, const char* valueName,
                         uint32_t type, const char* dataPreview)
    {
        Write("REGISTRY", callerRip, "%s\t%s\t%u\t%s",
              path ? path : "?", valueName ? valueName : "?", type, dataPreview ? dataPreview : "?");
    }

    // Capture file operation
    void CaptureFile(uint64_t callerRip, const char* path, uint32_t access, uint32_t disposition)
    {
        Write("FILE", callerRip, "%s\t%08X\t%08X", path ? path : "?", access, disposition);
    }

    // Capture memory allocation (for AllocTracker)
    void CaptureAlloc(uint64_t callerRip, void* addr, size_t size, uint32_t protect)
    {
        Write("ALLOC", callerRip, "%p\t%llu\t%08X", addr, (uint64_t)size, protect);
    }

    // Capture guard page / allocated memory CPUID event
    void CaptureGuardPageCpuid(uint64_t callerRip, uint32_t leaf, uint32_t subleaf,
                                uint32_t eax, uint32_t ebx, uint32_t ecx, uint32_t edx,
                                void* pageAddr)
    {
        Write("ALLOC_CPUID", callerRip, "%08X\t%08X\t%08X\t%08X\t%08X\t%08X\t%p",
              leaf, subleaf, eax, ebx, ecx, edx, pageAddr);
    }

    // Capture re-encrypt cycle
    void CaptureReencrypt(uint64_t callerRip, void* addr, uint32_t oldProtect, uint32_t newProtect)
    {
        Write("REENCRYPT", callerRip, "%p\t%08X\t%08X", addr, oldProtect, newProtect);
    }

    // Capture memory scan (canary hit)
    void CaptureCanaryHit(uint64_t callerRip, void* accessAddr)
    {
        Write("CANARY", callerRip, "%p", accessAddr);
    }

    // Capture network query (DNS, adapters, etc.)
    void CaptureNetwork(uint64_t callerRip, const char* type, const char* detail)
    {
        Write("NETWORK", callerRip, "%s\t%s", type ? type : "?", detail ? detail : "?");
    }

    // Capture DNS query
    void CaptureDns(uint64_t callerRip, const char* name)
    {
        Write("DNS", callerRip, "%s", name ? name : "?");
    }

    // Capture crypto query
    void CaptureCrypto(uint64_t callerRip, const char* provider, const char* operation)
    {
        Write("CRYPTO", callerRip, "%s\t%s", provider ? provider : "?", operation ? operation : "?");
    }

    // Capture GPU/driver query
    void CaptureGpu(uint64_t callerRip, const char* query)
    {
        Write("GPU", callerRip, "%s", query ? query : "?");
    }

    // Capture timing measurement
    void CaptureTiming(uint64_t callerRip, const char* type, uint64_t value)
    {
        Write("TIMING", callerRip, "%s\t%llu", type ? type : "?", value);
    }

    // Capture session/terminal query
    void CaptureSession(uint64_t callerRip, const char* type, uint32_t sessionId)
    {
        Write("SESSION", callerRip, "%s\t%u", type ? type : "?", sessionId);
    }

    // Capture generic probe
    void CaptureGeneric(uint64_t callerRip, const char* vector, const char* detail)
    {
        Write(vector ? vector : "UNKNOWN", callerRip, "%s", detail ? detail : "?");
    }

    // Capture timing delta between two successive events
    void CaptureDelta(uint64_t callerRip, uint64_t tscBefore, uint64_t tscAfter)
    {
        Write("TIMING_DELTA", callerRip, "%016llX\t%016llX\t%lld",
              tscBefore, tscAfter, tscAfter > tscBefore ? (tscAfter - tscBefore) : 0);
    }

private:
    FILE* m_file;
    LARGE_INTEGER m_qpf;
    LARGE_INTEGER m_qpcStart;
    uint64_t m_startTick;

    void Write(const char* vector, uint64_t callerRip, const char* fmt, ...)
    {
        if (!m_file) return;

        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        uint64_t elapsedUs = (uint64_t)((now.QuadPart - m_qpcStart.QuadPart) * 1000000 / m_qpf.QuadPart);
        uint32_t tid = (uint32_t)GetCurrentThreadId();

        fprintf(m_file, "%s\t%llu\t%u\t%016llX\t", vector, (unsigned long long)elapsedUs, tid, (unsigned long long)callerRip);

        va_list args;
        va_start(args, fmt);
        vfprintf(m_file, fmt, args);
        va_end(args);

        fprintf(m_file, "\n");
        fflush(m_file);

        // Rotate if file exceeds 100MB
        if (ftell(m_file) > 100 * 1024 * 1024) {
            fclose(m_file);
            m_file = nullptr;
            // open new file with timestamp
            wchar_t newPath[MAX_PATH];
            swprintf_s(newPath, L"capture_%llu.log", (unsigned long long)m_startTick);
            _wfopen_s(&m_file, newPath, L"w, ccs=UTF-8");
            if (m_file) {
                fprintf(m_file, "# Symbiote Capture Log (rotated)\n");
                fprintf(m_file, "# VECTOR\\ttimestamp_us\\ttid\\tcallerRip\\tfields...\n");
            }
        }
    }
};

// Global capture logger (set to nullptr for normal profile mode)
extern CaptureLogger* g_captureLogger;
