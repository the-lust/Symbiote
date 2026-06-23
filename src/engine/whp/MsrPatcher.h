#pragma once
#include <windows.h>
#include <unordered_map>
#include "Logger.h"

class IKernelBackend;

class MsrPatcher {
public:
    MsrPatcher(Logger* logger, IKernelBackend* backend);
    ~MsrPatcher();

    bool Initialize();
    void Shutdown();
    bool IsPatched() const { return m_initialized && !m_patches.empty(); }

private:
    struct PatchEntry {
        uint8_t originalByte;
        int instrLength;
        uint32_t msrIndex;
        bool isWrite;
    };

    using PatchMap = std::unordered_map<void*, PatchEntry>;

    Logger* m_logger;
    IKernelBackend* m_backend;
    PatchMap m_patches;
    void* m_vehHandle;
    CRITICAL_SECTION m_cs;
    bool m_initialized;

    bool ScanModule(const wchar_t* moduleName, uint8_t* baseAddr, SIZE_T moduleSize);
    bool ScanSection(uint8_t* sectionStart, SIZE_T sectionSize);

    uint64_t HandleMsrRead(uint32_t msr);

    static MsrPatcher* s_instance;
    static LONG CALLBACK VectoredHandler(EXCEPTION_POINTERS* ep);
    LONG OnException(EXCEPTION_POINTERS* ep);
};
