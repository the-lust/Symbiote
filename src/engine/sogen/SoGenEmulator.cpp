#include "SoGenEmulator.h"

SoGenEmulator::SoGenEmulator(Logger* logger, SyscallDispatcher* dispatcher)
    : m_logger(logger), m_dispatcher(dispatcher)
{
}

SoGenEmulator::~SoGenEmulator()
{
}

bool SoGenEmulator::EmulateSyscall(uint64_t syscallNumber, uint64_t* args, uint64_t* result)
{
    if (m_dispatcher) {
        return m_dispatcher->Dispatch(syscallNumber, args, result);
    }
    return false;
}
