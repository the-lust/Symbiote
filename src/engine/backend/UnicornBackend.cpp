// Credits: Unicorn fallback backend pattern adapted from Sogen (https://github.com/hedronium/Sogen)
#include "UnicornBackend.h"

// Register ID mapping for Unicorn Engine 2.x
// Map our CpuReg enum to Unicorn x86 register constants
static const int kCpuRegToUnicorn[] = {
    36,   // RAX  → UC_X86_REG_RAX
    41,   // RBX  → UC_X86_REG_RBX
    44,   // RCX  → UC_X86_REG_RCX
    51,   // RDX  → UC_X86_REG_RDX
    55,   // RSI  → UC_X86_REG_RSI
    46,   // RDI  → UC_X86_REG_RDI
    37,   // RBP  → UC_X86_REG_RBP
    54,   // RSP  → UC_X86_REG_RSP
    8,    // R8   → UC_X86_REG_R8
    9,    // R9   → UC_X86_REG_R9
    10,   // R10  → UC_X86_REG_R10
    11,   // R11  → UC_X86_REG_R11
    12,   // R12  → UC_X86_REG_R12
    13,   // R13  → UC_X86_REG_R13
    14,   // R14  → UC_X86_REG_R14
    15,   // R15  → UC_X86_REG_R15
    34,   // RIP  → UC_X86_REG_RIP
    25,   // RFLAGS → UC_X86_REG_EFLAGS
    23,   // CS   → UC_X86_REG_CS
    24,   // DS   → UC_X86_REG_DS
    26,   // ES   → UC_X86_REG_ES
    27,   // FS   → UC_X86_REG_FS
    28,   // GS   → UC_X86_REG_GS
    56,   // SS   → UC_X86_REG_SS
    46,   // CR0  → UC_X86_REG_CR0
    48,   // CR2  → UC_X86_REG_CR2 (corrected)
    49,   // CR3  → UC_X86_REG_CR3
    50,   // CR4  → UC_X86_REG_CR4
    16,   // DR0  → UC_X86_REG_DR0
    17,   // DR1  → UC_X86_REG_DR1
    18,   // DR2  → UC_X86_REG_DR2
    19,   // DR3  → UC_X86_REG_DR3
    20,   // DR6  → UC_X86_REG_DR6
    21,   // DR7  → UC_X86_REG_DR7
};

UnicornBackend::UnicornBackend(Logger* logger)
    : m_logger(logger)
    , m_ucEngine(nullptr)
    , m_hUnicorn(nullptr)
    , m_exitCount(0)
    , m_syscallCount(0)
    , m_running(false)
    , m_unicornAvailable(false)
{
    m_hUnicorn = LoadLibraryA("unicorn.dll");
    m_unicornAvailable = (m_hUnicorn != nullptr);
    if (m_unicornAvailable) {
        ResolveFunctions();
    }
}

UnicornBackend::~UnicornBackend()
{
    Stop();
    if (m_hUnicorn) {
        FreeLibrary(m_hUnicorn);
        m_hUnicorn = nullptr;
    }
}

bool UnicornBackend::ResolveFunctions()
{
    if (!m_hUnicorn) return false;
    p_uc_open       = (uc_open_t)GetProcAddress(m_hUnicorn, "uc_open");
    p_uc_close      = (uc_close_t)GetProcAddress(m_hUnicorn, "uc_close");
    p_uc_emu_start  = (uc_emu_start_t)GetProcAddress(m_hUnicorn, "uc_emu_start");
    p_uc_emu_stop   = (uc_emu_stop_t)GetProcAddress(m_hUnicorn, "uc_emu_stop");
    p_uc_reg_read   = (uc_reg_read_t)GetProcAddress(m_hUnicorn, "uc_reg_read");
    p_uc_reg_write  = (uc_reg_write_t)GetProcAddress(m_hUnicorn, "uc_reg_write");
    p_uc_mem_map_ptr = (uc_mem_map_ptr_t)GetProcAddress(m_hUnicorn, "uc_mem_map_ptr");
    p_uc_mem_unmap  = (uc_mem_unmap_t)GetProcAddress(m_hUnicorn, "uc_mem_unmap");
    p_uc_mem_read   = (uc_mem_read_t)GetProcAddress(m_hUnicorn, "uc_mem_read");
    p_uc_mem_write  = (uc_mem_write_t)GetProcAddress(m_hUnicorn, "uc_mem_write");
    p_uc_hook_add   = (uc_hook_add_t)GetProcAddress(m_hUnicorn, "uc_hook_add");
    p_uc_hook_del   = (uc_hook_del_t)GetProcAddress(m_hUnicorn, "uc_hook_del");
    p_uc_strerror   = (uc_strerror_t)GetProcAddress(m_hUnicorn, "uc_strerror");

    if (!p_uc_open || !p_uc_close || !p_uc_emu_start || !p_uc_emu_stop ||
        !p_uc_reg_read || !p_uc_reg_write || !p_uc_mem_map_ptr || !p_uc_mem_unmap ||
        !p_uc_mem_read || !p_uc_mem_write || !p_uc_hook_add || !p_uc_hook_del) {
        m_logger->Trace(LOG_WARNING, "UnicornBackend: unicorn.dll missing required exports");
        m_unicornAvailable = false;
        return false;
    }
    return true;
}

bool UnicornBackend::Initialize()
{
    if (!m_unicornAvailable || !p_uc_open) {
        m_logger->Trace(LOG_WARNING, "UnicornBackend: unicorn.dll not found or incomplete");
        return false;
    }

    void* uc = nullptr;
    int err = p_uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err || !uc) {
        const char* msg = p_uc_strerror ? p_uc_strerror(err) : "unknown";
        m_logger->Trace(LOG_ERROR, "UnicornBackend: uc_open failed: %s", msg);
        return false;
    }
    m_ucEngine = uc;

    // Set up hooks: code execution, interrupt (for SYSCALL)
    void* hookCode = nullptr;
    err = p_uc_hook_add(uc, &hookCode, UC_HOOK_CODE,
                         (void*)HookCodeCallback, this, 1, 0);
    if (err) {
        m_logger->Trace(LOG_WARNING, "UnicornBackend: uc_hook_add(CODE) failed (err=%d)", err);
    }

    void* hookIntr = nullptr;
    err = p_uc_hook_add(uc, &hookIntr, UC_HOOK_INTR,
                         (void*)HookIntrCallback, this, 1, 0);
    if (err) {
        m_logger->Trace(LOG_WARNING, "UnicornBackend: uc_hook_add(INTR) failed (err=%d)", err);
    }

    m_logger->Trace(LOG_INFO, "UnicornBackend initialized (x64, unicorn.dll)");
    return true;
}

bool UnicornBackend::Run()
{
    if (!m_ucEngine || !p_uc_emu_start) return false;
    m_running = true;

    uint64_t rip = ReadRegister(CpuReg::RIP);
    uint64_t endAddr = 0;
    int err = p_uc_emu_start(m_ucEngine, rip, endAddr, 1000 * 1000, 0);
    if (err) {
        const char* msg = p_uc_strerror ? p_uc_strerror(err) : "unknown";
        m_logger->Trace(LOG_WARNING, "UnicornBackend: uc_emu_start stopped: %s (err=%d)", msg, err);
    }

    m_running = false;
    m_exitCount++;
    return true;
}

bool UnicornBackend::Stop()
{
    if (m_ucEngine && p_uc_emu_stop) {
        p_uc_emu_stop(m_ucEngine);
    }
    m_running = false;
    if (m_ucEngine && p_uc_close) {
        p_uc_close(m_ucEngine);
        m_ucEngine = nullptr;
    }
    return true;
}

bool UnicornBackend::SingleStep()
{
    if (!m_ucEngine || !p_uc_emu_start) return false;

    uint64_t rip = ReadRegister(CpuReg::RIP);
    int err = p_uc_emu_start(m_ucEngine, rip, rip + 1, 0, 1);
    if (err) return false;
    m_exitCount++;
    return true;
}

int UnicornBackend::CpuRegToUnicorn(CpuReg reg) const
{
    int idx = (int)reg;
    if (idx < 0 || idx >= (int)(sizeof(kCpuRegToUnicorn)/sizeof(kCpuRegToUnicorn[0])))
        return -1;
    return kCpuRegToUnicorn[idx];
}

uint64_t UnicornBackend::ReadRegister(CpuReg reg)
{
    if (!m_ucEngine || !p_uc_reg_read) return 0;
    int ucReg = CpuRegToUnicorn(reg);
    if (ucReg < 0) return 0;
    uint64_t value = 0;
    int err = p_uc_reg_read(m_ucEngine, ucReg, &value);
    if (err) return 0;
    return value;
}

bool UnicornBackend::WriteRegister(CpuReg reg, uint64_t value)
{
    if (!m_ucEngine || !p_uc_reg_write) return false;
    int ucReg = CpuRegToUnicorn(reg);
    if (ucReg < 0) return false;
    int err = p_uc_reg_write(m_ucEngine, ucReg, &value);
    return (err == 0);
}

bool UnicornBackend::ReadMemory(uint64_t addr, void* buf, size_t size)
{
    if (!m_ucEngine || !p_uc_mem_read || !buf) return false;
    int err = p_uc_mem_read(m_ucEngine, addr, buf, size);
    return (err == 0);
}

bool UnicornBackend::WriteMemory(uint64_t addr, const void* buf, size_t size)
{
    if (!m_ucEngine || !p_uc_mem_write || !buf) return false;
    int err = p_uc_mem_write(m_ucEngine, addr, buf, size);
    return (err == 0);
}

uint64_t UnicornBackend::GetPhysicalAddress(uint64_t virtualAddr)
{
    // Unicorn uses flat address space — GPA == VA for identity mapping
    return virtualAddr;
}

uint32_t UnicornBackend::PermsToUnicorn(bool exec, bool write) const
{
    uint32_t p = UC_MEM_READ;
    if (write) p |= UC_MEM_WRITE;
    if (exec) p |= 4; // UC_MEM_EXEC = 4
    return p;
}

bool UnicornBackend::MapGuestMemory(uint64_t gpa, void* hostVa, size_t size, bool exec, bool write)
{
    if (!m_ucEngine || !p_uc_mem_map_ptr || !hostVa) return false;
    uint32_t perms = PermsToUnicorn(exec, write);
    int err = p_uc_mem_map_ptr(m_ucEngine, gpa, size, perms, hostVa);
    if (err) return false;
    m_mappedRegions[gpa] = {hostVa, size, perms};
    return true;
}

bool UnicornBackend::UnmapGuestMemory(uint64_t gpa, size_t size)
{
    if (!m_ucEngine || !p_uc_mem_unmap) return false;
    int err = p_uc_mem_unmap(m_ucEngine, gpa, size);
    if (err) return false;
    m_mappedRegions.erase(gpa);
    return true;
}

bool UnicornBackend::SetBreakpoint(uint64_t addr)
{
    if (!addr) return false;
    m_breakpoints[addr] = true;
    return true;
}

bool UnicornBackend::RemoveBreakpoint(uint64_t addr)
{
    m_breakpoints.erase(addr);
    return true;
}

bool UnicornBackend::HasBreakpoint(uint64_t addr) const
{
    auto it = m_breakpoints.find(addr);
    return it != m_breakpoints.end() && it->second;
}

bool UnicornBackend::IsRunning() const
{
    return m_running;
}

uint64_t UnicornBackend::GetExitCount() const
{
    return m_exitCount;
}

uint64_t UnicornBackend::GetSyscallCount() const
{
    return m_syscallCount;
}

bool UnicornBackend::SaveState(std::vector<uint8_t>& buffer)
{
    if (!m_ucEngine) return false;
    buffer.clear();
    // Save all GP registers
    CpuReg regs[] = {
        CpuReg::RAX, CpuReg::RBX, CpuReg::RCX, CpuReg::RDX,
        CpuReg::RSI, CpuReg::RDI, CpuReg::RBP, CpuReg::RSP,
        CpuReg::R8,  CpuReg::R9,  CpuReg::R10, CpuReg::R11,
        CpuReg::R12, CpuReg::R13, CpuReg::R14, CpuReg::R15,
        CpuReg::RIP, CpuReg::RFLAGS
    };
    auto put64 = [&](uint64_t v) {
        buffer.insert(buffer.end(), (uint8_t*)&v, (uint8_t*)&v + 8);
    };
    put64(m_exitCount);
    put64(m_syscallCount);
    for (auto& reg : regs) {
        put64(ReadRegister(reg));
    }
    return true;
}

bool UnicornBackend::RestoreState(const std::vector<uint8_t>& buffer)
{
    if (!m_ucEngine || buffer.size() < 18 * 8) return false;
    size_t offset = 0;
    auto read64 = [&]() -> uint64_t {
        if (offset + 8 > buffer.size()) return 0;
        uint64_t v; memcpy(&v, buffer.data() + offset, 8); offset += 8; return v;
    };
    m_exitCount = read64();
    m_syscallCount = read64();
    CpuReg regs[] = {
        CpuReg::RAX, CpuReg::RBX, CpuReg::RCX, CpuReg::RDX,
        CpuReg::RSI, CpuReg::RDI, CpuReg::RBP, CpuReg::RSP,
        CpuReg::R8,  CpuReg::R9,  CpuReg::R10, CpuReg::R11,
        CpuReg::R12, CpuReg::R13, CpuReg::R14, CpuReg::R15,
        CpuReg::RIP, CpuReg::RFLAGS
    };
    for (auto& reg : regs) {
        WriteRegister(reg, read64());
    }
    return true;
}

// ─── Hook callbacks ──────────────────────────────────────────────────

void UnicornBackend::HookCodeCallback(void* uc, uint64_t address, uint32_t size, void* userData)
{
    (void)uc; (void)size;
    UnicornBackend* self = (UnicornBackend*)userData;
    if (!self || !self->m_running) return;

    // Check for breakpoint hit
    if (self->HasBreakpoint(address)) {
        self->Stop();
        return;
    }

    uint8_t instr[2] = {0};
    if (self->p_uc_mem_read) {
        self->p_uc_mem_read(self->m_ucEngine, address, instr, 2);
    }
    if (instr[0] == 0x0F && instr[1] == 0x05) {
        self->m_syscallCount++;
        // Read RAX (syscall number), R10 (arg1), RDX (arg2), R8 (arg3), R9 (arg4)
        uint64_t rax = self->ReadRegister(CpuReg::RAX);
        // For SYSCALL, advance RIP past the instruction
        uint64_t rip = self->ReadRegister(CpuReg::RIP);
        self->WriteRegister(CpuReg::RIP, rip + 2);
        // Log the syscall and continue (host handles via fallthrough)
        self->m_logger->Trace(LOG_WHP, "Unicorn: SYSCALL 0x%llX at 0x%llX", rax, address);
    }
}

bool UnicornBackend::HookMemCallback(void* uc, uint64_t address, uint32_t size, uint32_t perm, void* userData)
{
    (void)uc; (void)size; (void)perm;
    UnicornBackend* self = (UnicornBackend*)userData;
    if (!self) return false;
    self->m_logger->Trace(LOG_WHP, "Unicorn: unmapped memory access at 0x%llX", address);
    return false; // Let Unicorn handle the fault
}

void UnicornBackend::HookIntrCallback(void* uc, uint32_t intno, void* userData)
{
    (void)uc;
    UnicornBackend* self = (UnicornBackend*)userData;
    if (!self) return;

    // INT 0x2E is a legacy syscall mechanism on Windows
    if (intno == 0x2E) {
        self->m_syscallCount++;
        uint64_t rax = self->ReadRegister(CpuReg::RAX);
        self->m_logger->Trace(LOG_WHP, "Unicorn: INT 0x2E syscall 0x%llX", rax);
        // Advance RIP past INT 0x2E (2 bytes)
        uint64_t rip = self->ReadRegister(CpuReg::RIP);
        self->WriteRegister(CpuReg::RIP, rip + 2);
    }
}
