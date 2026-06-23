#pragma once
#include <cstdint>
#include <windows.h>
#include "Logger.h"

class ObjectEmu {
public:
    explicit ObjectEmu(Logger* logger);
    ~ObjectEmu();

    bool HandleNtQueryObject(uint64_t* args, uint64_t* result);

private:
    Logger* m_logger;
};