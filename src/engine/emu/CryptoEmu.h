#pragma once
#include <cstdint>
#include <windows.h>
#include "Logger.h"

class CryptoEmu {
public:
    explicit CryptoEmu(Logger* logger);

    bool HandleNtQueryInformationToken(uint64_t* args, uint64_t* result);
    bool HandleNtOpenProcessToken(uint64_t* args, uint64_t* result);
    bool HandleNtDuplicateToken(uint64_t* args, uint64_t* result);
    bool HandleCryptGetProvParam(uint64_t* args, uint64_t* result);

private:
    Logger* m_logger;
};
