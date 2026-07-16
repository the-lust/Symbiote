#include "SteamGameDetector.h"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>

namespace fs = std::filesystem;

SteamGameDetector::SteamGameDetector()
{
    m_steamRoot = FindSteamRoot();
}

std::wstring SteamGameDetector::ReadRegistryString(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName)
{
    HKEY hSubKey;
    if (RegOpenKeyExW(hKey, subKey.c_str(), 0, KEY_READ, &hSubKey) != ERROR_SUCCESS)
        return L"";

    wchar_t buffer[MAX_PATH] = {0};
    DWORD size = sizeof(buffer);
    DWORD type = 0;
    LONG result = RegQueryValueExW(hSubKey, valueName.c_str(), NULL, &type, (LPBYTE)buffer, &size);
    RegCloseKey(hSubKey);

    if (result == ERROR_SUCCESS && type == REG_SZ)
        return std::wstring(buffer);

    return L"";
}

std::wstring SteamGameDetector::FindSteamRoot()
{
    // Check registry in priority order
    std::wstring path;

    // HKCU\Software\Valve\Steam\SteamPath
    path = ReadRegistryString(HKEY_CURRENT_USER, L"Software\\Valve\\Steam", L"SteamPath");
    if (!path.empty()) return path;

    // HKLM\SOFTWARE\Wow6432Node\Valve\Steam\InstallPath
    path = ReadRegistryString(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Wow6432Node\\Valve\\Steam", L"InstallPath");
    if (!path.empty()) return path;

    // HKLM\SOFTWARE\Valve\Steam\InstallPath
    path = ReadRegistryString(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Valve\\Steam", L"InstallPath");
    if (!path.empty()) return path;

    // Default paths
    std::vector<std::wstring> defaults = {
        L"C:\\Program Files (x86)\\Steam",
        L"C:\\Program Files\\Steam"
    };
    for (auto& d : defaults) {
        if (fs::exists(d)) return d;
    }

    return L"";
}

// ─── VDF Parser ───────────────────────────────────────────────────────

void SteamGameDetector::SkipWhitespace(const std::string& content, size_t& pos)
{
    while (pos < content.size()) {
        // Skip line comments
        if (pos + 1 < content.size() && content[pos] == '/' && content[pos + 1] == '/') {
            while (pos < content.size() && content[pos] != '\n') pos++;
            continue;
        }
        // Skip whitespace
        if (content[pos] == ' ' || content[pos] == '\t' || content[pos] == '\r' || content[pos] == '\n') {
            pos++;
            continue;
        }
        break;
    }
}

std::string SteamGameDetector::ReadQuotedString(const std::string& content, size_t& pos)
{
    std::string result;
    if (pos >= content.size() || content[pos] != '"') return result;
    pos++; // skip opening quote

    while (pos < content.size() && content[pos] != '"') {
        if (content[pos] == '\\' && pos + 1 < content.size()) {
            pos++;
            switch (content[pos]) {
                case 'n': result += '\n'; break;
                case 't': result += '\t'; break;
                case '\\': result += '\\'; break;
                case '"': result += '"'; break;
                default: result += content[pos]; break;
            }
        } else {
            result += content[pos];
        }
        pos++;
    }

    if (pos < content.size() && content[pos] == '"') pos++; // skip closing quote
    return result;
}

SteamGameDetector::VdfNode SteamGameDetector::ParseVdfRecursive(const std::string& content, size_t& pos)
{
    VdfNode node;

    // Read key
    SkipWhitespace(content, pos);
    if (pos >= content.size() || content[pos] != '"') return node;
    std::string key = ReadQuotedString(content, pos);
    node.key = std::wstring(key.begin(), key.end());

    SkipWhitespace(content, pos);
    if (pos >= content.size()) return node;

    if (content[pos] == '{') {
        // Block: has children
        pos++; // skip '{'
        while (pos < content.size()) {
            SkipWhitespace(content, pos);
            if (pos >= content.size()) break;
            if (content[pos] == '}') { pos++; break; }
            // Peek: if next non-whitespace is a quote, parse child
            if (content[pos] == '"') {
                auto child = ParseVdfRecursive(content, pos);
                if (!child.key.empty()) {
                    node.children.push_back(child);
                }
            } else {
                break; // unexpected
            }
        }
    } else {
        // Leaf: has a value
        if (content[pos] == '"') {
            std::string val = ReadQuotedString(content, pos);
            node.value = std::wstring(val.begin(), val.end());
        }
    }

    return node;
}

SteamGameDetector::VdfNode SteamGameDetector::ParseVdf(const std::string& content)
{
    size_t pos = 0;
    SkipWhitespace(content, pos);
    if (pos < content.size() && content[pos] == '"') {
        return ParseVdfRecursive(content, pos);
    }
    return VdfNode();
}

// ─── Library Enumeration ──────────────────────────────────────────────

std::vector<std::wstring> SteamGameDetector::EnumerateLibraryFolders(const std::wstring& steamRoot)
{
    std::vector<std::wstring> folders;
    folders.push_back(steamRoot); // Primary library

    // Parse libraryfolders.vdf
    fs::path vdfPath = fs::path(steamRoot) / L"steamapps" / L"libraryfolders.vdf";
    if (!fs::exists(vdfPath)) return folders;

    std::ifstream file(vdfPath);
    if (!file.is_open()) return folders;

    std::stringstream ss;
    ss << file.rdbuf();
    file.close();

    VdfNode root = ParseVdf(ss.str());

    // Root should have one child ("libraryfolders"), each numbered child has a "path"
    if (root.children.empty()) return folders;
    VdfNode& libFolders = root.children[0];

    for (auto& entry : libFolders.children) {
        for (auto& prop : entry.children) {
            if (prop.key == L"path" && !prop.value.empty()) {
                std::wstring libPath = prop.value;
                // Normalize forward slashes to backslashes
                std::replace(libPath.begin(), libPath.end(), L'/', L'\\');
                // Check if the path exists and is accessible
                if (fs::exists(libPath)) {
                    folders.push_back(libPath);
                }
                break;
            }
        }
    }

    return folders;
}

std::vector<SteamGame> SteamGameDetector::EnumerateInstalledGames()
{
    std::vector<SteamGame> games;
    if (m_steamRoot.empty()) return games;

    std::vector<std::wstring> libraries = EnumerateLibraryFolders(m_steamRoot);

    // Known tool app IDs (Steamworks tools, launcher apps, etc.)
    std::unordered_map<std::wstring, bool> knownTools;
    knownTools[L"228980"] = true; // Steamworks Common Redistributables

    for (auto& libPath : libraries) {
        fs::path appsDir = fs::path(libPath) / L"steamapps";
        if (!fs::exists(appsDir)) continue;

        // Find all appmanifest_*.acf files
        for (auto& entry : fs::directory_iterator(appsDir)) {
            if (!entry.is_regular_file()) continue;
            std::wstring filename = entry.path().filename().wstring();

            // Match appmanifest_<appid>.acf
            if (filename.find(L"appmanifest_") != 0) continue;
            if (filename.find(L".acf") == std::wstring::npos) continue;

            // Read the file
            std::ifstream file(entry.path());
            if (!file.is_open()) continue;
            std::stringstream ss;
            ss << file.rdbuf();
            file.close();

            VdfNode root = ParseVdf(ss.str());
            if (root.children.empty()) continue;
            VdfNode& appState = root.children[0];

            SteamGame game;
            for (auto& prop : appState.children) {
                if (prop.key == L"appid") game.appId = prop.value;
                else if (prop.key == L"name") game.name = prop.value;
                else if (prop.key == L"installdir") game.installDir = prop.value;
                else if (prop.key == L"SizeOnDisk") {
                    try { game.sizeOnDisk = std::stoull(prop.value); }
                    catch (...) { game.sizeOnDisk = 0; }
                }
            }

            if (game.installDir.empty()) continue;

            // Build full path
            game.fullPath = (fs::path(libPath) / L"steamapps" / L"common" / game.installDir).wstring();

            // Check if directory actually exists
            if (!fs::exists(game.fullPath)) continue;

            // Classify tools
            std::wstring lowerName = game.name;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
            game.isTool = knownTools.count(game.appId) > 0 ||
                lowerName.find(L"redistributable") != std::wstring::npos ||
                lowerName.find(L"dedicated server") != std::wstring::npos ||
                lowerName.find(L"soundtrack") != std::wstring::npos ||
                lowerName.find(L"sdk") != std::wstring::npos ||
                lowerName.find(L"steamworks") != std::wstring::npos;

            games.push_back(game);
        }
    }

    // Sort by name
    std::sort(games.begin(), games.end(),
        [](const SteamGame& a, const SteamGame& b) { return a.name < b.name; });

    return games;
}

// ─── Executable Scoring ───────────────────────────────────────────────

std::vector<std::wstring> SteamGameDetector::ScoreExecutables(
    const std::wstring& installDir, const std::wstring& gameName)
{
    struct ScoredExe {
        std::wstring relativePath;
        int64_t score;
    };
    std::vector<ScoredExe> scored;

    // Tokenize game name on non-alphanumeric
    std::wstring lowerName = gameName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
    std::vector<std::wstring> gameTokens;
    std::wstring current;
    for (wchar_t c : lowerName) {
        if (iswalnum(c)) {
            current += c;
        } else {
            if (current.size() >= 3) gameTokens.push_back(current);
            current.clear();
        }
    }
    if (current.size() >= 3) gameTokens.push_back(current);

    // Known junk exe patterns
    auto isJunk = [](const std::wstring& stem) -> bool {
        std::wstring s = stem;
        std::transform(s.begin(), s.end(), s.begin(), ::towlower);
        return s.find(L"crash") != std::wstring::npos ||
               s.find(L"error") != std::wstring::npos ||
               s.find(L"unins") != std::wstring::npos ||
               s.find(L"redist") != std::wstring::npos ||
               s.find(L"setup") != std::wstring::npos ||
               s.find(L"install") != std::wstring::npos ||
               s.find(L"vcredist") != std::wstring::npos ||
               s.find(L"dxsetup") != std::wstring::npos ||
               s == L"steam" || s == L"steamerror" ||
               s == L"update" || s == L"launcher";
    };

    // Walk the install directory (max depth 4)
    try {
        fs::path baseDir(installDir);
        int baseLen = (int)baseDir.wstring().size();

        for (auto& entry : fs::recursive_directory_iterator(
            baseDir, fs::directory_options::skip_permission_denied)) {

            if (!entry.is_regular_file()) continue;
            std::wstring ext = entry.path().extension().wstring();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
            if (ext != L".exe") continue;

            std::wstring fullPath = entry.path().wstring();
            std::wstring relative = fullPath.substr(baseLen);
            if (relative.size() > 0 && (relative[0] == L'/' || relative[0] == L'\\'))
                relative = relative.substr(1);

            // Calculate depth
            int depth = 0;
            for (wchar_t c : relative) if (c == L'\\' || c == L'/') depth++;
            if (depth > 4) continue;

            std::wstring filename = entry.path().stem().wstring();
            std::wstring lower = filename;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

            // Skip junk dirs (_CommonRedist, etc.)
            std::wstring pathLower = fullPath;
            std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::towlower);
            if (pathLower.find(L"_commonredist") != std::wstring::npos ||
                pathLower.find(L"redist") != std::wstring::npos) {
                continue;
            }

            int64_t score = 0;
            score -= depth * 25; // prefer shallow

            // Junk penalty
            if (isJunk(lower)) score -= 500;

            // Name match bonus
            for (auto& tok : gameTokens) {
                if (lower.find(tok) != std::wstring::npos) {
                    score += 40;
                }
            }

            // 64-bit bonus
            if (lower.find(L"_x64") != std::wstring::npos ||
                lower.find(L"win64") != std::wstring::npos ||
                lower.size() > 2 && lower.substr(lower.size() - 2) == L"64") {
                score += 5;
            }

            // Size bonus (bigger = more likely main exe, capped at +30)
            try {
                uint64_t size = (uint64_t)fs::file_size(entry.path());
                score += (int64_t)((std::min)(size / (1024ULL * 1024ULL), 30ULL));
            } catch (...) {}

            scored.push_back({relative, score});
        }
    } catch (...) {}

    // Sort by score descending
    std::sort(scored.begin(), scored.end(),
        [](const ScoredExe& a, const ScoredExe& b) { return a.score > b.score; });

    std::vector<std::wstring> result;
    for (auto& s : scored) {
        result.push_back(s.relativePath);
    }
    return result;
}

std::wstring SteamGameDetector::FindBestExecutable(
    const std::wstring& installDir, const std::wstring& gameName)
{
    auto scored = ScoreExecutables(installDir, gameName);
    if (scored.empty()) return L"";
    return scored[0];
}

SteamGame SteamGameDetector::FindGameByName(const std::wstring& partialName)
{
    SteamGame empty;
    auto games = EnumerateInstalledGames();

    std::wstring search = partialName;
    std::transform(search.begin(), search.end(), search.begin(), ::towlower);

    // First try exact match
    for (auto& g : games) {
        std::wstring name = g.name;
        std::transform(name.begin(), name.end(), name.begin(), ::towlower);
        if (name == search) return g;
    }

    // Then try contains
    for (auto& g : games) {
        std::wstring name = g.name;
        std::transform(name.begin(), name.end(), name.begin(), ::towlower);
        if (name.find(search) != std::wstring::npos) return g;
    }

    return empty;
}

std::wstring SteamGameDetector::FormatGameList(const std::vector<SteamGame>& games)
{
    std::wstring result;
    int count = 0;
    for (auto& g : games) {
        if (g.isTool) continue;
        result += g.name + L" (appid=" + g.appId + L")\n";
        count++;
    }
    return result;
}
