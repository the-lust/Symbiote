#include "VeSimulation.h"
#include <chrono>

VeSimulation::VeSimulation(Logger* logger)
    : m_logger(logger), m_initialized(false),
      m_veHandlerAddress(0),
      m_lastViolationRip(0), m_lastViolationTime(0), m_violationCount(0)
{
}

VeSimulation::~VeSimulation()
{
    Shutdown();
}

bool VeSimulation::Initialize()
{
    m_initialized = true;
    m_logger->Trace(LOG_INFO, "VeSimulation: #VE simulation initialized");
    return true;
}

void VeSimulation::Shutdown()
{
    m_initialized = false;
}

bool VeSimulation::HandleEptViolation(uint64_t gpa, uint64_t rip, WHV_MEMORY_ACCESS_TYPE accessType)
{
    if (!m_initialized) return false;

    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();

    if (rip == m_lastViolationRip) {
        m_violationCount++;
        if (m_violationCount > 10 && (now - m_lastViolationTime) < 100) {
            m_logger->Trace(LOG_WARNING,
                "VeSimulation: possible infinite loop at RIP=0x%llX - aborting #VE simulation", rip);
            m_violationCount = 0;
            return false;
        }
    } else {
        m_violationCount = 0;
        m_lastViolationRip = rip;
        m_lastViolationTime = now;
    }

    m_logger->Trace(LOG_EPT,
        "VeSimulation: #VE delivered GPA=0x%llX RIP=0x%llX type=%s",
        gpa, rip,
        accessType == WHvMemoryAccessRead ? "READ" :
        accessType == WHvMemoryAccessWrite ? "WRITE" : "EXECUTE");

    return true;
}
