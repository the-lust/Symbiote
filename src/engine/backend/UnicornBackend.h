#pragma once
#include "ICpuBackend.h"
#include "Logger.h"
#include <unordered_map>
#include <vector>
#include <cstdint>

// Unicorn Engine dynamic function pointer types (return uc_err = int)
typedef int  (*uc_open_t)(unsigned int arch, unsigned int mode, void** uc);
typedef int  (*uc_close_t)(void* uc);
typedef int  (*uc_emu_start_t)(void* uc, uint64_t begin, uint64_t until,
                                uint64_t timeout, size_t count);
typedef int  (*uc_emu_stop_t)(void* uc);
typedef int  (*uc_reg_read_t)(void* uc, int regid, void* value);
typedef int  (*uc_reg_write_t)(void* uc, int regid, const void* value);
typedef int  (*uc_mem_map_ptr_t)(void* uc, uint64_t address, size_t size,
                                  uint32_t perms, void* ptr);
typedef int  (*uc_mem_unmap_t)(void* uc, uint64_t address, size_t size);
typedef int  (*uc_mem_read_t)(void* uc, uint64_t address, void* bytes, size_t size);
typedef int  (*uc_mem_write_t)(void* uc, uint64_t address, const void* bytes, size_t size);
typedef int  (*uc_hook_add_t)(void* uc, void** hh, int type,
                               void* callback, void* user_data,
                               uint64_t begin, uint64_t end);
typedef int  (*uc_hook_del_t)(void* uc, void* hh);
typedef int  (*uc_ctl_get_t)(void* uc, int ctl, void* value);
typedef const char* (*uc_strerror_t)(int err);

// Unicorn constants
#define UC_API_MAJOR 2
#define UC_API_MINOR 1
#define UC_ARCH_X86 1
#define UC_MODE_64  (1 << 3)
#define UC_MODE_16  (1 << 1)
#define UC_MODE_32  (1 << 2)
#define UC_HOOK_CODE (1 << 0)
#define UC_HOOK_MEM_UNMAPPED (1 << 4)
#define UC_HOOK_INTR (1 << 14)
#define UC_MEM_READ 16
#define UC_MEM_WRITE 17

// x86 register IDs for Unicorn
#define UC_X86_REG_RAX 36
#define UC_X86_REG_RBX 41
#define UC_X86_REG_RCX 44
#define UC_X86_REG_RDX 51
#define UC_X86_REG_RSI 55
#define UC_X86_REG_RDI 46
#define UC_X86_REG_RBP 37
#define UC_X86_REG_RSP 54
#define UC_X86_REG_R8  8
#define UC_X86_REG_R9  9
#define UC_X86_REG_R10 10
#define UC_X86_REG_R11 11
#define UC_X86_REG_R12 12
#define UC_X86_REG_R13 13
#define UC_X86_REG_R14 14
#define UC_X86_REG_R15 15
#define UC_X86_REG_RIP 34
#define UC_X86_REG_EFLAGS 25
#define UC_X86_REG_CS 23
#define UC_X86_REG_DS 24
#define UC_X86_REG_ES 26
#define UC_X86_REG_FS 27
#define UC_X86_REG_GS 28
#define UC_X86_REG_SS 56
#define UC_X86_REG_CR0 46  // corrected ID for Unicorn 2.x
#define UC_X86_REG_CR3 49
#define UC_X86_REG_CR4 50
#define UC_X86_REG_DR0 16
#define UC_X86_REG_DR1 17
#define UC_X86_REG_DR2 18
#define UC_X86_REG_DR3 19
#define UC_X86_REG_DR6 20
#define UC_X86_REG_DR7 21

class UnicornBackend : public ICpuBackend {
public:
    explicit UnicornBackend(Logger* logger);
    ~UnicornBackend();

    CpuBackendType GetType() const override { return CpuBackendType::UNICORN; }
    bool Initialize() override;
    bool Run() override;
    bool Stop() override;
    bool SingleStep() override;
    uint64_t ReadRegister(CpuReg reg) override;
    bool WriteRegister(CpuReg reg, uint64_t value) override;
    bool ReadMemory(uint64_t addr, void* buf, size_t size) override;
    bool WriteMemory(uint64_t addr, const void* buf, size_t size) override;
    uint64_t GetPhysicalAddress(uint64_t virtualAddr) override;
    bool MapGuestMemory(uint64_t gpa, void* hostVa, size_t size, bool exec, bool write) override;
    bool UnmapGuestMemory(uint64_t gpa, size_t size) override;
    bool SetBreakpoint(uint64_t addr) override;
    bool RemoveBreakpoint(uint64_t addr) override;
    bool HasBreakpoint(uint64_t addr) const override;
    bool IsRunning() const override;
    uint64_t GetExitCount() const override;
    uint64_t GetSyscallCount() const override;
    bool SaveState(std::vector<uint8_t>& buffer) override;
    bool RestoreState(const std::vector<uint8_t>& buffer) override;

private:
    Logger* m_logger;
    void* m_ucEngine;
    HMODULE m_hUnicorn;
    uint64_t m_exitCount;
    uint64_t m_syscallCount;
    bool m_running;
    bool m_unicornAvailable;

    // Breakpoints: GPA → breakpoint flag
    std::unordered_map<uint64_t, bool> m_breakpoints;
    // Mapped memory: GPA → {hostVa, size, perms}
    struct MappedRegion {
        void* hostVa;
        size_t size;
        uint32_t perms;
    };
    std::unordered_map<uint64_t, MappedRegion> m_mappedRegions;

    // Resolved function pointers
    uc_open_t          p_uc_open;
    uc_close_t         p_uc_close;
    uc_emu_start_t     p_uc_emu_start;
    uc_emu_stop_t      p_uc_emu_stop;
    uc_reg_read_t      p_uc_reg_read;
    uc_reg_write_t     p_uc_reg_write;
    uc_mem_map_ptr_t   p_uc_mem_map_ptr;
    uc_mem_unmap_t     p_uc_mem_unmap;
    uc_mem_read_t      p_uc_mem_read;
    uc_mem_write_t     p_uc_mem_write;
    uc_hook_add_t      p_uc_hook_add;
    uc_hook_del_t      p_uc_hook_del;
    uc_strerror_t      p_uc_strerror;

    bool ResolveFunctions();
    int CpuRegToUnicorn(CpuReg reg) const;
    uint32_t PermsToUnicorn(bool exec, bool write) const;

    // Hook callbacks (static, dispatch to instance)
    static void HookCodeCallback(void* uc, uint64_t address, uint32_t size, void* userData);
    static bool HookMemCallback(void* uc, uint64_t address, uint32_t size, uint32_t perm, void* userData);
    static void HookIntrCallback(void* uc, uint32_t intno, void* userData);
};
