#pragma once
#include <windows.h>
#include "Logger.h"

class ModuleCloak {
public:
    explicit ModuleCloak(Logger* logger);
    ~ModuleCloak();

    bool CloakModule();
    bool HideFromPEB();
    bool HideFromLdr();
    // Unlinks from InLoadOrderModuleList — the list Module32First/Next (CreateToolhelp32Snapshot)
    // and most manual PEB-walking module enumerators actually use. A prior version only unlinked
    // InMemoryOrderModuleList and InInitializationOrderModuleList, leaving the module trivially
    // enumerable via the load-order list despite being called "cloaked".
    bool HideFromLoadOrderList();

private:
    Logger* m_logger;
    bool m_cloaked;
};
