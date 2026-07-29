#include "ProxyRenamer.h"
#include <cstdio>
#include <cstring>
#include <random>
#include <algorithm>

constexpr uint32_t kRenameTableMagic = 0x4D414E52; // 'RNAM'

ProxyRenamer::ProxyRenamer() : m_count(0), m_seed(0) {}
ProxyRenamer::~ProxyRenamer() {}

void ProxyRenamer::Init(uint64_t seed) {
    m_seed = seed;
    m_count = 0;
}

bool ProxyRenamer::RegisterDll(const wchar_t* originalName) {
    if (m_count >= kMaxProxyDlls) return false;
    wcscpy_s(m_entries[m_count].originalName, originalName);
    m_entries[m_count].randomName[0] = L'\0';
    m_entries[m_count].fileHash = HashName(originalName);
    m_count++;
    return true;
}

void ProxyRenamer::GenerateNames() {
    for (size_t i = 0; i < m_count; i++) {
        GenerateOneName(i, m_entries[i].randomName, MAX_PATH);
    }
}

bool ProxyRenamer::ApplyRenames(const wchar_t* targetDir) {
    wchar_t srcPath[MAX_PATH], dstPath[MAX_PATH];

    for (size_t i = 0; i < m_count; i++) {
        swprintf_s(srcPath, L"%s\\%s", targetDir, m_entries[i].originalName);
        swprintf_s(dstPath, L"%s\\%s", targetDir, m_entries[i].randomName);

        // Safety: don't overwrite existing file
        if (GetFileAttributesW(dstPath) != INVALID_FILE_ATTRIBUTES) {
            // File already exists from a previous run — delete first
            DeleteFileW(dstPath);
        }

        if (!CopyFileW(srcPath, dstPath, FALSE)) {
            return false;
        }
    }
    return true;
}

void ProxyRenamer::BuildTable(RenameTable* outTable) const {
    outTable->magic = kRenameTableMagic;
    outTable->entryCount = (uint32_t)m_count;
    outTable->runSeed = m_seed;
    for (size_t i = 0; i < m_count; i++) {
        outTable->entries[i] = m_entries[i];
    }
}

const wchar_t* ProxyRenamer::GetRandomName(const wchar_t* original) const {
    for (size_t i = 0; i < m_count; i++) {
        if (_wcsicmp(m_entries[i].originalName, original) == 0) {
            return m_entries[i].randomName;
        }
    }
    return nullptr;
}

bool ProxyRenamer::RestoreNames(const wchar_t* targetDir) {
    wchar_t srcPath[MAX_PATH], dstPath[MAX_PATH];
    for (size_t i = 0; i < m_count; i++) {
        swprintf_s(srcPath, L"%s\\%s", targetDir, m_entries[i].randomName);
        // Delete the random-named copy (original stays)
        DeleteFileW(srcPath);
    }
    return true;
}

bool ProxyRenamer::CleanupRandomFiles(const wchar_t* targetDir) {
    wchar_t path[MAX_PATH];
    for (size_t i = 0; i < m_count; i++) {
        swprintf_s(path, L"%s\\%s", targetDir, m_entries[i].randomName);
        DeleteFileW(path);
    }
    return true;
}

void ProxyRenamer::GenerateOneName(uint64_t index, wchar_t* out, size_t outLen) {
    // Deterministic random from seed + index
    uint64_t h = m_seed ^ index;
    h ^= h >> 33;
    h *= 0xFF51AFD7ED558CCDULL;
    h ^= h >> 33;
    h *= 0xC4CEB9FE1A85EC53ULL;
    h ^= h >> 33;
    uint32_t nameVal = (uint32_t)(h & 0xFFFFFFFF);

    swprintf_s(out, outLen, L"%08X.dll", nameVal);
}

uint64_t ProxyRenamer::HashName(const wchar_t* name) const {
    uint64_t hash = 0xCBF29CE484222325ULL;
    while (*name) {
        hash ^= (wchar_t)towlower(*name);
        hash *= 0x100000001B3ULL;
        name++;
    }
    return hash;
}