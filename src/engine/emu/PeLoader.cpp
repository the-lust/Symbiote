#include "PeLoader.h"
#include <cstring>
#include <fstream>
#include <algorithm>

PeLoader::PeLoader(Logger* logger)
    : m_logger(logger)
{
}

PeLoader::~PeLoader()
{
}

bool PeLoader::IsPeImage(const uint8_t* data, size_t size)
{
    if (size < sizeof(IMAGE_DOS_HEADER)) return false;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > (LONG)size) return false;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;
    return true;
}

PIMAGE_NT_HEADERS PeLoader::GetNtHeaders(const uint8_t* data, size_t size)
{
    if (!IsPeImage(data, size)) return nullptr;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)data;
    return (IMAGE_NT_HEADERS*)(data + dos->e_lfanew);
}

bool PeLoader::LoadImage(const std::wstring& path, uint8_t** outImage, size_t* outSize)
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        m_logger->Trace(LOG_ERROR, "PeLoader: cannot open %ls", path.c_str());
        return false;
    }

    std::streamoff tellResult = file.tellg();
    if (tellResult <= 0) {
        m_logger->Trace(LOG_ERROR, "PeLoader: empty or unreadable file %ls", path.c_str());
        return false;
    }
    size_t size = (size_t)tellResult;
    file.seekg(0, std::ios::beg);

    uint8_t* data = new uint8_t[size];
    file.read((char*)data, size);
    file.close();

    if (!IsPeImage(data, size)) {
        delete[] data;
        m_logger->Trace(LOG_ERROR, "PeLoader: invalid PE image %ls", path.c_str());
        return false;
    }

    *outImage = data;
    *outSize = size;
    m_logger->Trace(LOG_INFO, "PeLoader: loaded %ls (%zu bytes)", path.c_str(), size);
    return true;
}

// Returns true if [offset, offset+len) lies entirely within [0, size).
static bool RangeInBounds(uint64_t offset, uint64_t len, size_t size)
{
    if (offset >= size) return false;
    uint64_t end = offset + len;
    if (end < offset) return false; // overflow
    return end <= size;
}

bool PeLoader::ResolveImports(uint8_t* image, size_t size)
{
    PIMAGE_NT_HEADERS nt = GetNtHeaders(image, size);
    if (!nt) return false;

    IMAGE_DATA_DIRECTORY importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size == 0) return true;
    if (!RangeInBounds(importDir.VirtualAddress, importDir.Size, size)) {
        m_logger->Trace(LOG_ERROR, "PeLoader: import directory out of bounds");
        return false;
    }

    uint8_t* const imageEnd = image + size;
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(image + importDir.VirtualAddress);

    while ((uint8_t*)(importDesc + 1) <= imageEnd && importDesc->Name) {
        if (!RangeInBounds(importDesc->Name, 1, size)) { importDesc++; continue; }

        const char* dllName = (const char*)(image + importDesc->Name);
        // Bound the string scan to the remaining image so LoadLibraryA never reads past the buffer.
        size_t maxLen = imageEnd - (uint8_t*)dllName;
        if (strnlen(dllName, maxLen) >= maxLen) { importDesc++; continue; }

        // try to load the DLL
        HMODULE hDll = LoadLibraryA(dllName);
        if (!hDll) {
            m_logger->Trace(LOG_WARNING, "PeLoader: cannot load %s", dllName);
            importDesc++;
            continue;
        }

        if (!RangeInBounds(importDesc->FirstThunk, sizeof(IMAGE_THUNK_DATA), size) ||
            !RangeInBounds(importDesc->OriginalFirstThunk, sizeof(IMAGE_THUNK_DATA), size)) {
            importDesc++;
            continue;
        }

        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(image + importDesc->FirstThunk);
        PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)(image + importDesc->OriginalFirstThunk);

        while ((uint8_t*)(thunk + 1) <= imageEnd && (uint8_t*)(origThunk + 1) <= imageEnd && thunk->u1.Function) {
            uintptr_t funcAddr = 0;

            if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                // ordinal import
                funcAddr = (uintptr_t)GetProcAddress(hDll, (LPCSTR)(origThunk->u1.Ordinal & 0xFFFF));
            } else if (RangeInBounds(origThunk->u1.AddressOfData, sizeof(IMAGE_IMPORT_BY_NAME), size)) {
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(image + origThunk->u1.AddressOfData);
                funcAddr = (uintptr_t)GetProcAddress(hDll, importByName->Name);
            }

            if (funcAddr) {
                thunk->u1.Function = funcAddr;
            }

            thunk++;
            origThunk++;
        }

        importDesc++;
    }

    m_logger->Trace(LOG_EMU, "PeLoader: imports resolved");
    return true;
}

bool PeLoader::ApplyRelocations(uint8_t* image, size_t size, uint64_t baseAddr)
{
    PIMAGE_NT_HEADERS nt = GetNtHeaders(image, size);
    if (!nt) return false;

    uint64_t delta = baseAddr - nt->OptionalHeader.ImageBase;
    if (delta == 0) return true;

    IMAGE_DATA_DIRECTORY relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.Size == 0) return true;
    if (!RangeInBounds(relocDir.VirtualAddress, relocDir.Size, size)) {
        m_logger->Trace(LOG_ERROR, "PeLoader: relocation directory out of bounds");
        return false;
    }

    uint8_t* const imageEnd = image + size;
    uint8_t* relocData = image + relocDir.VirtualAddress;
    uint8_t* relocEnd = relocData + relocDir.Size; // already validated <= imageEnd above

    while (relocData + sizeof(IMAGE_BASE_RELOCATION) <= relocEnd) {
        IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)relocData;
        if (reloc->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;
        if (relocData + reloc->SizeOfBlock > relocEnd) break; // block claims to run past the directory

        int count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entries = (WORD*)(relocData + sizeof(IMAGE_BASE_RELOCATION));

        for (int i = 0; i < count; i++) {
            WORD offset = entries[i] & 0xFFF;
            WORD type = (entries[i] >> 12) & 0xF;

            uint64_t patchOffset = (uint64_t)reloc->VirtualAddress + offset;
            size_t patchSize = (type == IMAGE_REL_BASED_DIR64) ? sizeof(uint64_t) : sizeof(uint32_t);
            if (!RangeInBounds(patchOffset, patchSize, size)) continue; // patch target outside the image, skip

            uintptr_t* patchAddr = (uintptr_t*)(image + patchOffset);
            (void)imageEnd;

            switch (type) {
                case IMAGE_REL_BASED_DIR64:
                    *patchAddr += delta;
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    *(uint32_t*)patchAddr += (uint32_t)delta;
                    break;
                case IMAGE_REL_BASED_ABSOLUTE:
                    break;
                default:
                    break;
            }
        }

        relocData += reloc->SizeOfBlock;
    }

    m_logger->Trace(LOG_EMU, "PeLoader: relocations applied (delta=0x%llX)", delta);
    return true;
}

uint64_t PeLoader::GetEntryPoint(uint8_t* image, size_t size)
{
    PIMAGE_NT_HEADERS nt = GetNtHeaders(image, size);
    if (!nt) return 0;
    return nt->OptionalHeader.AddressOfEntryPoint;
}

std::vector<PeLoader::ImportedFunction> PeLoader::GetImports(uint8_t* image, size_t size)
{
    std::vector<ImportedFunction> imports;
    PIMAGE_NT_HEADERS nt = GetNtHeaders(image, size);
    if (!nt) return imports;

    IMAGE_DATA_DIRECTORY importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size == 0) return imports;
    if (!RangeInBounds(importDir.VirtualAddress, importDir.Size, size)) return imports;

    uint8_t* const imageEnd = image + size;
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(image + importDir.VirtualAddress);

    while ((uint8_t*)(importDesc + 1) <= imageEnd && importDesc->Name) {
        if (!RangeInBounds(importDesc->Name, 1, size) ||
            !RangeInBounds(importDesc->OriginalFirstThunk, sizeof(IMAGE_THUNK_DATA), size)) {
            importDesc++;
            continue;
        }

        const char* dllName = (const char*)(image + importDesc->Name);
        size_t maxLen = imageEnd - (uint8_t*)dllName;
        if (strnlen(dllName, maxLen) >= maxLen) { importDesc++; continue; }

        PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)(image + importDesc->OriginalFirstThunk);

        while ((uint8_t*)(origThunk + 1) <= imageEnd && origThunk->u1.Function) {
            ImportedFunction imp;
            imp.dllName = dllName;

            if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                imp.funcName = "ordinal_" + std::to_string(origThunk->u1.Ordinal & 0xFFFF);
            } else if (RangeInBounds(origThunk->u1.AddressOfData, sizeof(IMAGE_IMPORT_BY_NAME), size)) {
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(image + origThunk->u1.AddressOfData);
                imp.funcName = importByName->Name;
            } else {
                origThunk++;
                continue;
            }

            imp.address = 0;
            imports.push_back(imp);
            origThunk++;
        }

        importDesc++;
    }

    return imports;
}