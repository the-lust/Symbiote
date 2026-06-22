#include "ExitDispatcher.h"
#include <cstring>

ExitDispatcher::ExitDispatcher(Logger* logger)
    : m_logger(logger)
{
    memset(m_handlers, 0, sizeof(m_handlers));
}

ExitDispatcher::~ExitDispatcher()
{
}

void ExitDispatcher::RegisterHandler(WHV_RUN_VP_EXIT_REASON reason, IExitHandler* handler)
{
    if (reason < 256) {
        m_handlers[(int)reason] = handler;
        m_logger->Trace(LOG_WHP, "Exit handler registered for reason %d", (int)reason);
    }
}

bool ExitDispatcher::Dispatch(WHV_VP_EXIT_CONTEXT* ctx, WHV_RUN_VP_EXIT_CONTEXT* exitCtx, uint64_t* rip)
{
    WHV_RUN_VP_EXIT_REASON reason = exitCtx->ExitReason;

    if (reason < 256 && m_handlers[(int)reason]) {
        return m_handlers[(int)reason]->HandleExit(ctx, exitCtx, rip);
    }

    m_logger->Trace(LOG_WHP, "Unhandled exit reason: %d (0x%X)", reason, reason);
    return false;
}
