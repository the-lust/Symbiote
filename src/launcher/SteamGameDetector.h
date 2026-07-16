#pragma once
#define NOMINMAX
#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>

struct SteamGame {
    std::wstring appId;
    std::wstring name;
    std::wstring installDir;   // Inside steamapps/common/
    std::wstring fullPath;     // Absolute path on host
    uint64_t sizeOnDisk;
    bool isTool;
};

class SteamGameDetector {
public:
    SteamGameDetector();

    // Find Steam root from registry
    std::wstring FindSteamRoot();

    // Enumerate all library folders (primary + from libraryfolders.vdf)
    std::vector<std::wstring> EnumerateLibraryFolders(const std::wstring& steamRoot);

    // Enumerate all installed games from all libraries
    std::vector<SteamGame> EnumerateInstalledGames();

    // Score executables in a game directory to find the main game exe
    // Returns sorted (best first) list of relative exe paths
    std::vector<std::wstring> ScoreExecutables(const std::wstring& installDir, const std::wstring& gameName);

    // Find best executable for a game
    std::wstring FindBestExecutable(const std::wstring& installDir, const std::wstring& gameName);

    // Find a game by name (partial match, case-insensitive)
    SteamGame FindGameByName(const std::wstring& partialName);

    // List all games as a formatted string (for console output)
    std::wstring FormatGameList(const std::vector<SteamGame>& games);

private:
    struct VdfNode {
        std::wstring key;
        std::wstring value;        // leaf value
        std::vector<VdfNode> children; // child nodes
    };

    // Simple VDF text parser
    VdfNode ParseVdf(const std::string& content);
    VdfNode ParseVdfRecursive(const std::string& content, size_t& pos);

    // Skip whitespace and comments
    void SkipWhitespace(const std::string& content, size_t& pos);
    std::string ReadQuotedString(const std::string& content, size_t& pos);

    // Registry helpers
    std::wstring ReadRegistryString(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName);

    std::wstring m_steamRoot;
};
