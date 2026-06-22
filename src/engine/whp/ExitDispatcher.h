#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include "Logger.h"

class IExitHandler {
public:
    virtual ~IExitHandler() = default;
    virtual bool HandleExit(WHV_VP_EXIT_CONTEXT* ctx, WHV_RUN_VP_EXIT_CONTEXT* exitCtx, uint64_t* rip) = 0;
    virtual WHV_RUN_VP_EXIT_REASON GetExitReason() const = 0;
};

class ExitDispatcher {
public:
    explicit ExitDispatcher(Logger* logger);
    ~ExitDispatcher();

    void RegisterHandler(WHV_RUN_VP_EXIT_REASON reason, IExitHandler* handler);
    bool Dispatch(WHV_VP_EXIT_CONTEXT* ctx, WHV_RUN_VP_EXIT_CONTEXT* exitCtx, uint64_t* rip);

private:
    Logger* m_logger;
    IExitHandler* m_handlers[256];
};
