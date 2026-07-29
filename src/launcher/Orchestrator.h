#pragma once
#include <windows.h>
#include <cstdint>
#include "../engine/whp/ConfigSnapshot.h"
#include "ProxyRenamer.h"

// Orchestrator manages the full startup sequence:
// Phase 0: INI bake → ConfigSnapshot (done by launcher entry)
// Phase 1: BYOVD detect & open
// Phase 2: Kernel proxy injection (SSDT, EPROCESS, LSTAR, IDT)
// Phase 3: VHDX mount / sandbox setup
// Phase 4: WHP partition + VCPU creation
// Phase 5: Proxy DLL rename
// Phase 6: Inject engine + config snapshot into target
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
    // Returns the final ConfigSnapshot ready for engine injection
    const ConfigSnapshot* Run();

    // Individual phase execution (for granular error handling)
    PhaseResult Phase0_BakeConfig(const wchar_t* iniPath);
    PhaseResult Phase1_ByovdDetect();
    PhaseResult Phase2_KernelProxyInject();
    PhaseResult Phase3_SandboxSetup();
    PhaseResult Phase4_PartitionCreate();
    PhaseResult Phase5_RenameDlls();
    PhaseResult Phase6_InjectEngine();
    PhaseResult Phase7_ResumeTarget();

    // Tear down everything in reverse order
    void Shutdown();

    // Accessors
    const ConfigSnapshot* GetConfig() const { return m_config; }
    const DetectedDriver* GetDriver() const { return m_driver; }
    ProxyRenamer* GetRenamer() { return &m_renamer; }

private:
    // Generate random seed for this run (from BCrypt or RDRAND)
    uint64_t GenerateSeed();

    ConfigSnapshot* m_config;
    DetectedDriver* m_driver;
    ProxyRenamer   m_renamer;
    HANDLE         m_hTargetProcess;
    HANDLE         m_hTargetThread;
    uint32_t       m_targetPid;
    uint64_t       m_seed;
    bool           m_active;
};