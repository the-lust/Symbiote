// Credits: Unicorn fallback backend pattern adapted from Sogen (https://github.com/hedronium/Sogen)
#include "UnicornBackend.h"

UnicornBackend::UnicornBackend(Logger* logger)
    : m_logger(logger)
    , m_ucEngine(nullptr)
    , m_exitCount(0)
    , m_syscallCount(0)
    , m_running(false)
    , m_unicornAvailable(false)
{
    HMODULE hUnicorn = LoadLibraryA("unicorn.dll");
    m_unicornAvailable = (hUnicorn != nullptr);
    if (hUnicorn) FreeLibrary(hUnicorn);
}

UnicornBackend::~UnicornBackend()
{
    Stop();
}

bool UnicornBackend::Initialize()
{
    if (!m_unicornAvailable) {
        m_logger->Trace(LOG_WARNING, "UnicornBackend: unicorn.dll not found, falling back");
        return false;
    }
    return true;
}

bool UnicornBackend::Run() { m_running = true; return true; }
bool UnicornBackend::Stop() { m_running = false; return true; }
bool UnicornBackend::SingleStep() { return false; }

uint64_t UnicornBackend::ReadRegister(CpuReg reg) { (void)reg; return 0; }
bool UnicornBackend::WriteRegister(CpuReg reg, uint64_t value) { (void)reg; (void)value; return false; }
bool UnicornBackend::ReadMemory(uint64_t addr, void* buf, size_t size) { (void)addr; (void)buf; (void)size; return false; }
bool UnicornBackend::WriteMemory(uint64_t addr, const void* buf, size_t size) { (void)addr; (void)buf; (void)size; return false; }
uint64_t UnicornBackend::GetPhysicalAddress(uint64_t virtualAddr) { (void)virtualAddr; return 0; }
bool UnicornBackend::MapGuestMemory(uint64_t gpa, void* hostVa, size_t size, bool exec, bool write) { (void)gpa; (void)hostVa; (void)size; (void)exec; (void)write; return false; }
bool UnicornBackend::UnmapGuestMemory(uint64_t gpa, size_t size) { (void)gpa; (void)size; return false; }
bool UnicornBackend::SetBreakpoint(uint64_t addr) { m_breakpoints[addr] = true; return true; }
bool UnicornBackend::RemoveBreakpoint(uint64_t addr) { m_breakpoints.erase(addr); return true; }
bool UnicornBackend::HasBreakpoint(uint64_t addr) const { return m_breakpoints.count(addr) > 0; }
bool UnicornBackend::IsRunning() const { return m_running; }
uint64_t UnicornBackend::GetExitCount() const { return m_exitCount; }
uint64_t UnicornBackend::GetSyscallCount() const { return m_syscallCount; }
bool UnicornBackend::SaveState(std::vector<uint8_t>& buffer) { (void)buffer; return false; }
bool UnicornBackend::RestoreState(const std::vector<uint8_t>& buffer) { (void)buffer; return false; }

void UnicornBackend::HookCodeCallback(void* uc, uint64_t address, uint32_t size, void* userData) { (void)uc; (void)address; (void)size; (void)userData; }
void UnicornBackend::HookMemCallback(void* uc, uint64_t address, uint32_t size, void* userData) { (void)uc; (void)address; (void)size; (void)userData; }
