#pragma once
#include <windows.h>
#include <WinHvPlatform.h>
#include <cstdint>
#include "Logger.h"

// #VE (Virtualization Exception) simulation via EPT violation handling
// WHP does not support true #VE, but we can simulate direct-to-ring-3
// EPT violation delivery by handling MemoryAccess exits differently:
// - When a user-mode EPT violation occurs, instead of causing a full VM exit,
//   we inject a software exception into the guest
// - The guest's existing VEH handler catches it and processes it
// - This reduces VM exit overhead for memory access violations

class VeSimulation {
public:
    explicit VeSimulation(Logger* logger);
    ~VeSimulation();

    bool Initialize();
    void Shutdown();

    // Handle an EPT violation for #VE simulation
    // Returns true if the violation was handled (injected as #VE)
    // Returns false if it should be treated as a normal EPT violation
    bool HandleEptViolation(uint64_t gpa, uint64_t rip, WHV_MEMORY_ACCESS_TYPE accessType);

    // Set the #VE handler address in the guest
    void SetVeHandlerAddress(uint64_t address) { m_veHandlerAddress = address; }

private:
    Logger* m_logger;
    bool m_initialized;
    uint64_t m_veHandlerAddress;

    // Track recent violations to prevent infinite loops
    uint64_t m_lastViolationRip;
    uint64_t m_lastViolationTime;
    uint32_t m_violationCount;
};
