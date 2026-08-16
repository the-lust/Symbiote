#pragma once
#include <windows.h>
#include <string>

// External tool integration: unpackers (Steam/SteamStub chain), debuggers,
// disassemblers, tracers, and the AI report analyzer, all driven from
// [tools] in config.ini and launcher CLI flags (--tool / --unpack / --analyze).
// Tools are never bundled — paths point at locally installed binaries.
class ToolKit {
public:
    ToolKit(const std::string& configPath, const std::wstring& exeDir);

    // Path from [tools] <configKey>; empty if not configured.
    std::wstring GetToolPath(const std::string& configKey) const;
    bool ToolConfigured(const std::string& configKey) const;

    // Spawn <tool> against target; %TARGET%/%OUTDIR% tokens in default args
    // are substituted, target appended if no %TARGET%. Returns exit code.
    bool RunTool(const std::string& configKey, const std::wstring& target,
                 const std::wstring& outDir, int* exitCode, std::wstring* outError = nullptr);

    // Steam/SteamStub unpack chain: steamless -> gbe -> opensteamtools ->
    // steamsls -> steamvent -> steamdira. First success wins; the unpacked
    // exe path is returned. Research use only, on binaries you own.
    bool UnpackTarget(const std::wstring& target, std::wstring* unpackedOut);

    // Print availability table to stdout.
    void ListTools() const;

    // Write dump report.json for the AI analyzer (target, config summary,
    // tool availability, dump file list).
    bool WriteReport(const std::wstring& dumpDir, const std::wstring& target,
                     const std::wstring& unpacked) const;

    // Run the configured [tools] ai_analyzer against a report; falls back to
    // "python tools/ai_analyze.py" if python is on PATH.
    bool RunAnalyzer(const std::wstring& reportPath) const;

private:
    std::string  m_configPath;
    std::wstring m_exeDir;
};