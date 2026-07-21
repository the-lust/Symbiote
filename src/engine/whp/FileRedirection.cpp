#include "FileRedirection.h"
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

FileRedirection* g_fileRedirection = nullptr;

FileRedirection::FileRedirection(Logger* logger)
    : m_logger(logger)
    , m_initialized(false)
{
}

FileRedirection::~FileRedirection()
{
    g_fileRedirection = nullptr;
}

bool FileRedirection::Initialize(const wchar_t* boxName)
{
    m_boxName = boxName;
    m_boxRoot = L"\\Sandbox\\" + std::wstring(boxName) + L"\\user\\current\\";

    m_rules.clear();

    PathRule defaultRule;
    defaultRule.hostPrefix = L"\\??\\C:\\Users\\";
    defaultRule.boxPathPrefix = L"\\Sandbox\\" + std::wstring(boxName) + L"\\user\\current\\";
    defaultRule.readOnly = false;
    defaultRule.recursive = true;
    m_rules.push_back(defaultRule);

    PathRule programRule;
    programRule.hostPrefix = L"\\??\\C:\\Program Files";
    programRule.boxPathPrefix = L"\\Sandbox\\" + std::wstring(boxName) + L"\\user\\current\\ProgramFiles";
    programRule.readOnly = true;
    programRule.recursive = true;
    m_rules.push_back(programRule);

    PathRule systemRule;
    systemRule.hostPrefix = L"\\??\\C:\\Windows";
    systemRule.boxPathPrefix = L"\\Sandbox\\" + std::wstring(boxName) + L"\\user\\current\\Windows";
    systemRule.readOnly = true;
    systemRule.recursive = true;
    m_rules.push_back(systemRule);

    m_initialized = true;
    m_logger->Trace(LOG_INFO, "FileRedirection: initialized for box '%ls'", boxName);
    return true;
}

void FileRedirection::AddRule(const PathRule& rule)
{
    m_rules.push_back(rule);
}

bool FileRedirection::GetRedirectedPath(const wchar_t* hostPath, std::wstring& outBoxPath, bool /*isWrite*/)
{
    if (!m_initialized) return false;

    std::wstring norm = NormalizePath(hostPath);
    if (norm.empty()) return false;

    for (const auto& rule : m_rules) {
        std::wstring relative;
        if (IsPathUnderRule(norm, rule, relative)) {
            if (rule.readOnly) {
                outBoxPath = norm;
                return true;
            }
            outBoxPath = rule.boxPathPrefix + relative;
            return true;
        }
    }

    outBoxPath = norm;
    return false;
}

bool FileRedirection::GetTruePath(const wchar_t* boxPath, std::wstring& outHostPath)
{
    std::wstring norm = NormalizePath(boxPath);
    if (norm.empty()) return false;

    for (const auto& rule : m_rules) {
        if (norm.find(rule.boxPathPrefix) == 0) {
            outHostPath = rule.hostPrefix + norm.substr(rule.boxPathPrefix.length());
            return true;
        }
    }

    outHostPath = norm;
    return false;
}

bool FileRedirection::EnsureWriteCopy(const wchar_t* hostPath)
{
    std::wstring boxPath;
    if (!GetRedirectedPath(hostPath, boxPath, true))
        return false;

    if (boxPath == NormalizePath(hostPath))
        return true;

    if (GetFileAttributesW(boxPath.c_str()) != INVALID_FILE_ATTRIBUTES)
        return true;

    return CopyFileToBox(hostPath, boxPath.c_str());
}

bool FileRedirection::EnumerateMerged(const wchar_t* dirPath,
                                       std::vector<std::wstring>& outEntries)
{
    std::wstring norm = NormalizePath(dirPath);
    if (norm.empty()) return false;

    std::wstring boxDir;
    GetRedirectedPath(norm.c_str(), boxDir, false);

    std::wstring searchHost = norm + L"\\*";
    WIN32_FIND_DATAW ffd;
    HANDLE hFind = FindFirstFileW(searchHost.c_str(), &ffd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(ffd.cFileName, L".") != 0 && wcscmp(ffd.cFileName, L"..") != 0)
                outEntries.push_back(ffd.cFileName);
        } while (FindNextFileW(hFind, &ffd));
        FindClose(hFind);
    }

    if (!boxDir.empty() && boxDir != norm) {
        std::wstring searchBox = boxDir + L"\\*";
        hFind = FindFirstFileW(searchBox.c_str(), &ffd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                bool found = false;
                for (const auto& e : outEntries) {
                    if (_wcsicmp(e.c_str(), ffd.cFileName) == 0) {
                        found = true;
                        break;
                    }
                }
                if (!found && wcscmp(ffd.cFileName, L".") != 0 && wcscmp(ffd.cFileName, L"..") != 0)
                    outEntries.push_back(ffd.cFileName);
            } while (FindNextFileW(hFind, &ffd));
            FindClose(hFind);
        }
    }

    return true;
}

bool FileRedirection::Resolve(const wchar_t* path, bool isWrite, FileInfo& info)
{
    std::wstring norm = NormalizePath(path);
    info.truePath = norm;

    if (GetRedirectedPath(norm.c_str(), info.boxPath, isWrite)) {
        info.isRedirected = (info.boxPath != norm);
        info.isWriteCopy = isWrite && info.isRedirected;
        return true;
    }

    info.boxPath = norm;
    info.isRedirected = false;
    info.isWriteCopy = false;
    return true;
}

bool FileRedirection::IsPathUnderRule(const std::wstring& path, const PathRule& rule, std::wstring& relative)
{
    size_t pos = path.find(rule.hostPrefix);
    if (pos != 0) return false;

    relative = path.substr(rule.hostPrefix.length());

    if (!rule.recursive) {
        if (relative.find(L'\\') != std::wstring::npos)
            return false;
    }

    return true;
}

std::wstring FileRedirection::GetBoxPathFor(const std::wstring& hostFullPath)
{
    std::wstring result;
    GetRedirectedPath(hostFullPath.c_str(), result, true);
    return result;
}

std::wstring FileRedirection::NormalizePath(const wchar_t* path)
{
    if (!path || !path[0]) return L"";

    std::wstring result;
    if (path[0] == L'\\' && path[1] == L'\\' && path[2] == L'?' && path[3] == L'\\') {
        result = path;
    } else if (path[0] == L'\\' && path[1] == L'\\' && path[2] == L'.' && path[3] == L'\\') {
        result = path;
    } else if (path[0] >= L'A' && path[0] <= L'Z' && path[1] == L':') {
        result = std::wstring(L"\\??\\") + path;
    } else if (path[0] >= L'a' && path[0] <= L'z' && path[1] == L':') {
        result = std::wstring(L"\\??\\") + (wchar_t)(path[0] - 32) + (path + 1);
    } else {
        result = path;
    }

    for (size_t i = 0; i < result.length(); i++) {
        if (result[i] == L'/')
            result[i] = L'\\';
    }

    return result;
}

bool FileRedirection::CopyFileToBox(const wchar_t* hostPath, const wchar_t* boxPath)
{
    if (!CopyFileW(hostPath, boxPath, FALSE)) {
        DWORD gle = GetLastError();
        if (gle == ERROR_PATH_NOT_FOUND) {
            std::wstring dir = boxPath;
            size_t pos = dir.rfind(L'\\');
            if (pos != std::wstring::npos) {
                dir = dir.substr(0, pos);
                size_t cur = 3;
                while ((cur = dir.find(L'\\', cur + 1)) != std::wstring::npos) {
                    CreateDirectoryW(dir.substr(0, cur).c_str(), NULL);
                }
                CreateDirectoryW(dir.c_str(), NULL);
                if (CopyFileW(hostPath, boxPath, FALSE))
                    return true;
            }
        }
        m_logger->Trace(LOG_WARNING, "FileRedirection: copy failed: %ls -> %ls (GLE=%u)",
            hostPath, boxPath, GetLastError());
        return false;
    }
    return true;
}
