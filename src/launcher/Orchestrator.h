#pragma once
#include <windows.h>
#include <cstdint>
#include "../shared/SharedMemory.h"
#include "../engine/whp/ConfigSnapshot.h"
#include "ProxyRenamer.h"

// Forward declarations
struct DetectedDriver;

// Orchestrator manages the full startup sequence:
// Phase 0: INI bake → ConfigSnapshot (done by launcher entry)
// Phase 1: BYOVD detect & open
// Phase 2: Kernel proxy injection (SSDT, EPROCESS, LSTAR, IDT)
// Phase 3: VHDX mount / sandbox setup
// Phase 4: WHP partition config (deferred to engine)
// Phase 5: Proxy DLL rename + copy to target dir
// Phase 6: Create target process, inject engine + shared memory
// Phase 7: Resume target process

struct PhaseResult {
    bool success;
    uint32_t phaseId;
    wchar_t errorMsg[256];
};

class Orchestrator {
public:
    Orchestrator();
    ~Orchestrator();

    // Main entry: run ALL phases
    const ConfigSnapshot* Run();

    // Individual phase execution
    PhaseResult Phase0_BakeConfig(const wchar_t* iniPath);
    PhaseResult Phase1_ByovdDetect();
    PhaseResult Phase2_KernelProxyInject();
    PhaseResult Phase3_SandboxSetup();
    PhaseResult Phase4_PartitionCreate();
    PhaseResult Phase5_RenameDlls();
    PhaseResult Phase6_InjectEngine();
    PhaseResult Phase7_ResumeTarget();

    // Tear down everything
    void Shutdown();

    // Accessors
    const ConfigSnapshot* GetConfig() const { return m_config; }
    ProxyRenamer* GetRenamer() { return &m_renamer; }
    const PROCESS_INFORMATION& GetProcessInfo() const { return m_pi; }
    uint64_t GetRunSeed() const { return m_seed; }

private:
    uint64_t GenerateSeed();
    bool CreateSharedMemory();
    void DestroySharedMemory();

    ConfigSnapshot* m_config;
    DetectedDriver* m_driver;
    ProxyRenamer    m_renamer;
    uint64_t        m_seed;
    bool            m_active;

    // Process management
    PROCESS_INFORMATION m_pi;
    STARTUPINFOW        m_si;
    HANDLE              m_hTargetProcess;
    HANDLE              m_hTargetThread;
    uint32_t            m_targetPid;

    // Shared memory
    HANDLE  m_hSharedMem;
    void*   m_hSharedMemMap;
};