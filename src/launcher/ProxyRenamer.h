#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <array>

constexpr size_t kMaxProxyDlls = 32;

struct RenameTableEntry {
    wchar_t originalName[MAX_PATH];  // original name on disk (e.g., L"engine.dll")
    wchar_t randomName[MAX_PATH];    // random hex name (e.g., L"7F3A1B2E.dll")
    uint64_t fileHash;               // SHA-256 truncated for verification
};

struct RenameTable {
    uint32_t magic;                  // 'RNAM'
    uint32_t entryCount;
    uint64_t runSeed;
    RenameTableEntry entries[kMaxProxyDlls];
};

class ProxyRenamer {
public:
    ProxyRenamer();
    ~ProxyRenamer();

    // Initialize with a seed for deterministic-but-unique random names
    void Init(uint64_t seed);

    // Register a file for renaming
    bool RegisterDll(const wchar_t* originalName);

    // Generate all random names
    void GenerateNames();

    // Perform the actual file renames (copy to new names)
    // Returns false if any file already exists (safe check)
    bool ApplyRenames(const wchar_t* targetDir);

    // Build the rename table for engine communication
    void BuildTable(RenameTable* outTable) const;

    // Get the random name for a given original
    const wchar_t* GetRandomName(const wchar_t* original) const;

    // Restore original file names
    bool RestoreNames(const wchar_t* targetDir);

    // Clean up random-named files
    bool CleanupRandomFiles(const wchar_t* targetDir);

private:
    // Generate a single random hex name (8 hex digits + .dll)
    void GenerateOneName(uint64_t index, wchar_t* out, size_t outLen);

    // 64-bit FNV-1a hash of the name
    uint64_t HashName(const wchar_t* name) const;

    std::array<RenameTableEntry, kMaxProxyDlls> m_entries;
    size_t m_count;
    uint64_t m_seed;
};