#pragma once
#include <cstdint>
#include <windows.h>
#include "Logger.h"

class ThreadManager {
public:
    explicit ThreadManager(Logger* logger);

    bool HandleNtCreateThread(uint64_t* args, uint64_t* result);
    bool HandleNtOpenThread(uint64_t* args, uint64_t* result);
    bool HandleNtSuspendThread(uint64_t* args, uint64_t* result);
    bool HandleNtResumeThread(uint64_t* args, uint64_t* result);
    bool HandleNtTerminateThread(uint64_t* args, uint64_t* result);
    bool HandleNtGetContextThread(uint64_t* args, uint64_t* result);
    bool HandleNtSetContextThread(uint64_t* args, uint64_t* result);
    bool HandleNtQueryInformationThread(uint64_t* args, uint64_t* result);

    bool HandleNtCreateEvent(uint64_t* args, uint64_t* result);
    bool HandleNtSetEvent(uint64_t* args, uint64_t* result);
    bool HandleNtWaitForSingleObject(uint64_t* args, uint64_t* result);
    bool HandleNtWaitForMultipleObjects(uint64_t* args, uint64_t* result);
    bool HandleNtSignalAndWaitForSingleObject(uint64_t* args, uint64_t* result);

private:
    Logger* m_logger;
};
