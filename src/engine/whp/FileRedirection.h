#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include "Logger.h"

class FileRedirection {
public:
    explicit FileRedirection(Logger* logger);
    ~FileRedirection();

    struct PathRule {
        std::wstring hostPrefix;    // e.g. C:\Users\...
        std::wstring boxPathPrefix; // e.g. \Sandbox\DefaultBox\...
        bool         readOnly;
        bool         recursive;
    };

    struct FileInfo {
        std::wstring truePath;   // real host path
        std::wstring boxPath;    // sandbox path (copy destination)
        bool         isRedirected;
        bool         isWriteCopy;
    };

    bool Initialize(const wchar_t* boxName);
    void AddRule(const PathRule& rule);

    // Resolve a host path to its sandbox-redirected form
    bool GetRedirectedPath(const wchar_t* hostPath, std::wstring& outBoxPath, bool isWrite);

    // Get the true host path from a sandbox path
    bool GetTruePath(const wchar_t* boxPath, std::wstring& outHostPath);

    // Copy-on-write: copy host file to box path before modification
    bool EnsureWriteCopy(const wchar_t* hostPath);

    // Merge enumeration: combine host + box directory entries
    bool EnumerateMerged(const wchar_t* dirPath,
                         std::vector<std::wstring>& outEntries);

    // Query redirection info for a given path
    bool Resolve(const wchar_t* path, bool isWrite, FileInfo& info);

    bool IsInitialized() const { return m_initialized; }

private:
    Logger* m_logger;
    bool m_initialized;
    std::wstring m_boxName;
    std::wstring m_boxRoot;
    std::vector<PathRule> m_rules;

    bool IsPathUnderRule(const std::wstring& path, const PathRule& rule, std::wstring& relative);
    std::wstring GetBoxPathFor(const std::wstring& hostFullPath);
    std::wstring NormalizePath(const wchar_t* path);
    bool CopyFileToBox(const wchar_t* hostPath, const wchar_t* boxPath);
};

extern FileRedirection* g_fileRedirection;
