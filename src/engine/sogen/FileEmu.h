#pragma once
#include <cstdint>
#include <vector>
#include <windows.h>
#include "Logger.h"

class FileEmu {
public:
    explicit FileEmu(Logger* logger);

    bool HandleNtCreateFile(uint64_t* args, uint64_t* result);
    bool HandleNtReadFile(uint64_t* args, uint64_t* result);
    bool HandleNtWriteFile(uint64_t* args, uint64_t* result);
    bool HandleNtQueryInformationFile(uint64_t* args, uint64_t* result);
    bool HandleNtQueryVolumeInformationFile(uint64_t* args, uint64_t* result);
    bool HandleNtDeviceIoControlFile(uint64_t* args, uint64_t* result);
    bool HandleNtQueryAttributesFile(uint64_t* args, uint64_t* result);
    bool HandleNtOpenFile(uint64_t* args, uint64_t* result);
    bool HandleNtDeleteFile(uint64_t* args, uint64_t* result);
    bool HandleNtQueryDirectoryFile(uint64_t* args, uint64_t* result);
    bool HandleNtNotifyChangeDirectoryFile(uint64_t* args, uint64_t* result);

private:
    Logger* m_logger;

    struct VirtualFile {
        uint64_t handle;
        std::wstring name;
        uint64_t size;
    };

    std::vector<VirtualFile> m_virtualFiles;
    bool IsSensitiveFile(const std::wstring& path) const;
};
