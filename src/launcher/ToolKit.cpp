#include "ToolKit.h"
#include "ConfigParser.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstdio>

namespace fs = std::filesystem;

struct ToolDef {
    const char*   configKey;   // [tools] key
    const char*   display;     // human name
    const char*   defaultArgs; // "", "%TARGET%", "%OUTDIR%" tokens
};

// Steam/SteamStub unpack chain (research use on binaries you own).
// Steamless uses -O <outdir> -p <exe>; the rest are run with the target as
// their primary argument (their CLIs differ; overridden by config if needed
// via the [tools] path + a future [tools.<name>_args] override).
static const ToolDef kUnpackers[] = {
    { "steamless",      "Steamless (SteamStub unpacker)",   "-O \"%OUTDIR%\" -p \"%TARGET%\"" },
    { "gbe",            "GBE",                              "\"%TARGET%\"" },
    { "opensteamtools", "OpenSteamTools",                   "\"%TARGET%\"" },
    { "steamsls",       "SteamSls",                         "\"%TARGET%\"" },
    { "steamvent",      "SteamVent",                        "\"%TARGET%\"" },
    { "steamdira",      "SteamDira",                        "\"%TARGET%\"" },
};

// Analysis/debug tool registry.
static const ToolDef kAnalyzers[] = {
    { "ce",     "Cheat Engine",          "\"%TARGET%\"" },
    { "ghidra", "Ghidra",                "\"%TARGET%\"" },
    { "x64dbg", "x64dbg",                "\"%TARGET%\"" },
    { "binja",  "Binary Ninja",          "\"%TARGET%\"" },
    { "ida",    "IDA / IDA Pro",         "\"%TARGET%\"" },
    { "pin",    "Intel PIN",             "-- \"%TARGET%\"" },
};

ToolKit::ToolKit(const std::string& configPath, const std::wstring& exeDir)
    : m_configPath(configPath), m_exeDir(exeDir)
{
}

std::wstring ToolKit::GetToolPath(const std::string& configKey) const
{
    ConfigParser cfg(m_configPath);
    if (!cfg.Load()) return L"";
    std::string p = cfg.GetString("tools", configKey, "");
    if (p.empty()) return L"";
    std::wstring w(p.begin(), p.end());
    return w;
}

bool ToolKit::ToolConfigured(const std::string& configKey) const
{
    ConfigParser cfg(m_configPath);
    if (!cfg.Load()) return false;
    return !cfg.GetString("tools", configKey, "").empty();
}

static bool FileExists(const std::wstring& path)
{
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

bool ToolKit::RunTool(const std::string& configKey, const std::wstring& target,
                      const std::wstring& outDir, int* exitCode, std::wstring* outError)
{
    std::wstring tool = GetToolPath(configKey);
    if (tool.empty()) {
        if (outError) *outError = L"tool '" + std::wstring(configKey.begin(), configKey.end()) + L"' not configured in [tools]";
        return false;
    }
    if (!FileExists(tool)) {
        if (outError) *outError = L"tool not found: " + tool;
        return false;
    }

    const ToolDef* def = nullptr;
    for (const auto& t : kUnpackers)  if (configKey == t.configKey) def = &t;
    for (const auto& t : kAnalyzers)  if (configKey == t.configKey) def = &t;

    std::wstring args;
    if (def && def->defaultArgs[0]) {
        std::wstring tmpl;
        for (const char* a = def->defaultArgs; *a; a++) tmpl += (wchar_t)(unsigned char)*a;
        auto ReplaceAll = [](std::wstring& s, const std::wstring& from, const std::wstring& to) {
            size_t pos = 0;
            while ((pos = s.find(from, pos)) != std::wstring::npos) {
                s.replace(pos, from.size(), to);
                pos += to.size();
            }
        };
        ReplaceAll(tmpl, L"%TARGET%", L"\"" + target + L"\"");
        ReplaceAll(tmpl, L"%OUTDIR%", L"\"" + outDir + L"\"");
        args = tmpl;
    } else {
        args = L"\"" + target + L"\"";
    }

    std::wstring cmdline = L"\"" + tool + L"\" " + args;
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(tool.c_str(), &cmdline[0], nullptr, nullptr, FALSE, 0,
                        nullptr, nullptr, &si, &pi)) {
        if (outError) *outError = L"CreateProcess failed: " + tool + L" (error " + std::to_wstring(GetLastError()) + L")";
        return false;
    }
    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    if (exitCode) *exitCode = (int)code;
    return code == 0;
}

static std::wstring FirstExeInDir(const std::wstring& dir, const std::wstring& preferredBase)
{
    if (!preferredBase.empty()) {
        std::wstring candidate = dir + L"\\" + preferredBase;
        if (FileExists(candidate)) return candidate;
    }
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW((dir + L"\\*.exe").c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return L"";
    std::wstring found = dir + L"\\" + fd.cFileName;
    FindClose(hFind);
    return found;
}

bool ToolKit::UnpackTarget(const std::wstring& target, std::wstring* unpackedOut)
{
    fs::path tpath(target);
    std::wstring base = tpath.stem().wstring();
    ConfigParser cfg(m_configPath);
    std::wstring dumpRoot;
    if (cfg.Load()) {
        std::string d = cfg.GetString("tools", "unpack_dir", "");
        if (!d.empty()) dumpRoot.assign(d.begin(), d.end());
    }
    if (dumpRoot.empty()) dumpRoot = m_exeDir + L"\\dump";
    std::wstring outDir = dumpRoot + L"\\" + base + L"\\unpacked";
    std::error_code ec;
    fs::create_directories(outDir, ec);

    for (const auto& t : kUnpackers) {
        if (!ToolConfigured(t.configKey)) continue;
        printf("[unpack] trying %s ...\n", t.display);
        int exitCode = -1;
        std::wstring err;
        if (!RunTool(t.configKey, target, outDir, &exitCode, &err)) {
            printf("[unpack] %s unavailable: %ls\n", t.display, err.c_str());
            continue;
        }
        if (exitCode != 0) {
            printf("[unpack] %s exited with %d\n", t.display, exitCode);
            continue;
        }
        std::wstring result = FirstExeInDir(outDir, base + L".exe");
        if (!result.empty()) {
            if (unpackedOut) *unpackedOut = result;
            printf("[unpack] succeeded via %s -> %ls\n", t.display, result.c_str());
            return true;
        }
        printf("[unpack] %s succeeded but produced no exe in %ls\n", t.display, outDir.c_str());
    }
    return false;
}

void ToolKit::ListTools() const
{
    printf("=== External tools ([tools] in config.ini) ===\n");
    auto Print = [&](const ToolDef* defs, size_t n) {
        for (size_t i = 0; i < n; i++) {
            std::wstring path = GetToolPath(defs[i].configKey);
            bool ok = !path.empty() && FileExists(path);
            printf("  %-16s %-30s [%s]\n", defs[i].configKey, defs[i].display,
                   ok ? "OK" : "not configured");
            if (!path.empty() && !ok) printf("    -> path missing: %ls\n", path.c_str());
        }
    };
    Print(kUnpackers, sizeof(kUnpackers) / sizeof(kUnpackers[0]));
    Print(kAnalyzers, sizeof(kAnalyzers) / sizeof(kAnalyzers[0]));
}

static std::string WToUtf8(const std::wstring& w)
{
    if (w.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], len, nullptr, nullptr);
    return s;
}

bool ToolKit::WriteReport(const std::wstring& dumpDir, const std::wstring& target,
                          const std::wstring& unpacked) const
{
    std::error_code ec;
    fs::create_directories(dumpDir, ec);
    std::wstring reportPath = dumpDir + L"\\report.json";

    ConfigParser cfg(m_configPath);
    if (!cfg.Load()) return false;

    std::ostringstream os;
    os << "{\n"
       << "  \"tool\": \"Symbiote\",\n"
       << "  \"target\": \"" << WToUtf8(target) << "\",\n"
       << "  \"unpacked\": \"" << WToUtf8(unpacked) << "\",\n"
       << "  \"spoof_vectors\": {"
       << "\"cpuid\": " << (cfg.GetBool("cpuid", "status", cfg.GetBool("stealth", "always_on", true)) ? "true" : "false")
       << ", \"rdtsc\": " << (cfg.GetBool("rdtsc", "status", cfg.GetBool("stealth", "always_on", true)) ? "true" : "false")
       << ", \"msr\": " << (cfg.GetBool("msr", "status", cfg.GetBool("stealth", "always_on", true)) ? "true" : "false")
       << ", \"kuser\": " << (cfg.GetBool("kuser", "status", cfg.GetBool("stealth", "always_on", true)) ? "true" : "false")
       << "},\n"
       << "  \"stealth_always_on\": " << (cfg.GetBool("stealth", "always_on", true) ? "true" : "false") << ",\n"
       << "  \"hypervisor_mode\": \"" << cfg.GetString("hypervisor", "mode", "whp") << "\",\n"
       << "  \"tools\": [";
    bool first = true;
    auto DumpTools = [&](const ToolDef* defs, size_t n) {
        for (size_t i = 0; i < n; i++) {
            std::wstring path = GetToolPath(defs[i].configKey);
            os << (first ? "" : ",") << "{\"name\": \"" << defs[i].display
               << "\", \"available\": " << (ToolConfigured(defs[i].configKey) ? "true" : "false")
               << ", \"path\": \"" << WToUtf8(path) << "\"}";
            first = false;
        }
    };
    DumpTools(kUnpackers, sizeof(kUnpackers) / sizeof(kUnpackers[0]));
    DumpTools(kAnalyzers, sizeof(kAnalyzers) / sizeof(kAnalyzers[0]));
    os << "],\n";

    os << "  \"dump_files\": [";
    bool f2 = true;
    int count = 0;
    for (const auto& entry : fs::recursive_directory_iterator(dumpDir, ec)) {
        if (ec) break;
        if (entry.is_regular_file()) {
            os << (f2 ? "" : ",") << "\"" << WToUtf8(entry.path().wstring()) << "\"";
            f2 = false;
            if (++count >= 100) break;
        }
    }
    os << "],\n  \"dump_file_count\": " << count << "\n}\n";

    std::ofstream out(reportPath);
    if (!out) return false;
    out << os.str();
    out.close();

    printf("[report] wrote %ls\n", reportPath.c_str());
    return true;
}

bool ToolKit::RunAnalyzer(const std::wstring& reportPath) const
{
    std::wstring analyzer = GetToolPath("ai_analyzer");
    std::wstring cmdline;
    if (!analyzer.empty()) {
        std::wstring tmpl = analyzer;
        size_t pos = tmpl.find(L"%REPORT%");
        if (pos != std::wstring::npos) {
            tmpl.replace(pos, 8, L"\"" + reportPath + L"\"");
        } else {
            tmpl += L" \"" + reportPath + L"\"";
        }
        cmdline = tmpl;
    } else {
        cmdline = L"python tools\\ai_analyze.py \"" + reportPath + L"\"";
    }

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(nullptr, &cmdline[0], nullptr, nullptr, FALSE, 0,
                        nullptr, nullptr, &si, &pi)) {
        printf("[analyze] no ai_analyzer configured and python not usable "
               "(%d). Run: python tools\\ai_analyze.py %ls\n",
               (int)GetLastError(), reportPath.c_str());
        return false;
    }
    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    return code == 0;
}