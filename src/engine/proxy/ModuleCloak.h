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

private:
    Logger* m_logger;
    bool m_cloaked;
};
