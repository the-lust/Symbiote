#pragma once
#include <windows.h>
#include <cstdint>

// Shared memory protocol between launcher and engine.
// The launcher creates a file mapping before engine injection.
// The engine maps it at init, reads config, then unmaps.
//
// Layout:
//   [0]   SharedMemoryHeader
//   [64]  ConfigSnapshot (padded to page align)
//   [N]   ExportEntry array
//   [M]   RenameTable

constexpr uint32_t kSharedMemMagic   = 0x534D5942; // 'SYMB'
constexpr uint32_t kSharedMemVersion = 1;

// Export entry for function address table
struct ExportEntry {
    uint32_t funcId;    // ExportFuncId
    uint64_t funcPtr;   // address in engine address space
};

struct SharedMemoryHeader {
    uint32_t magic;                     // kSharedMemMagic
    uint32_t version;                   // kSharedMemVersion
    uint32_t totalSize;                 // total mapping size in bytes
    uint32_t configSnapshotOffset;      // offset from header to ConfigSnapshot
    uint32_t exportTableOffset;         // offset from header to ExportEntry array
    uint32_t exportTableCount;          // number of ExportEntry entries
    uint32_t renameTableOffset;         // offset from header to RenameTable
    uint32_t renameTableEntryCount;     // number of RenameTableEntry entries
    uint64_t runSeed;                   // unique seed for this run
    uint32_t reserved[15];
};

// Build the shared memory name with a unique suffix per run
inline void BuildSharedMemName(uint64_t runSeed, wchar_t* out, size_t outLen) {
    swprintf_s(out, outLen, L"Global\\Symbiote_Config_%016llX", runSeed);
}