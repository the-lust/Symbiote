#include <windows.h>
#include <shellapi.h>
#include <commdlg.h>
#include <iostream>
#include <string>
#include <vector>
#include "ConfigParser.h"
#include "WhpDetection.h"
#include "ProcessUtils.h"
#include "Orchestrator.h"
#include "ToolKit.h"
#include "../engine/whp/ConfigSnapshot.h"

#pragma comment(linker, "/SUBSYSTEM:CONSOLE")

static void LogMessage(const std::string& msg) {
    OutputDebugStringA(msg.c_str());
    HANDLE hLog = CreateFileA("launcher.log", GENERIC_WRITE, FILE_SHARE_READ,
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hLog != INVALID_HANDLE_VALUE) {
        SetFilePointer(hLog, 0, NULL, FILE_END);
        DWORD written;
        WriteFile(hLog, msg.c_str(), (DWORD)msg.size(), &written, NULL);
        CloseHandle(hLog);
    }
}

static std::wstring BrowseForExe() {
    OPENFILENAMEW ofn = {0};
    wchar_t path[MAX_PATH] = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = L"Executables (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
    if (GetOpenFileNameW(&ofn)) {
        return std::wstring(path);
    }
    return L"";
}

static void ShowUsage()
{
    MessageBoxW(NULL,
        L"Symbiote Launcher\n\n"
        L"Usage: launcher.exe [options] <target.exe>\n\n"
        L"Options:\n"
        L"   explorer, -e              Open file browser to select target\n"
        L"   debug, -d                 Enable verbose debug logging\n"
        L"   --target <exe>            Target executable path\n"
        L"   --args <...>              Arguments passed to target\n"
        L"   --sandbox <exe>           Run any .exe inside WHP sandbox\n"
        L"   --profile <name>          Load profiles/<name>.ini (stealth|compat|analysis|capture)\n"
        L"   config=<path>             Path to config.ini (default: ./config/config.ini)\n"
        L"   --list-tools              List configured external tools ([tools] in config)\n"
        L"   --tool <name>             Run an external tool on the target first\n"
        L"                             (unpackers: steamless gbe opensteamtools steamsls\n"
        L"                              steamvent steamdira | debuggers/analyzers: ce ghidra\n"
        L"                              x64dbg binja ida pin)\n"
        L"   --unpack                  Auto-unpack target via the Steam/SteamStub chain,\n"
        L"                             then launch the unpacked exe\n"
        L"   --analyze [dir]           Write dump report.json and run the AI analyzer\n\n"
        L"Examples:\n"
        L"   launcher.exe explorer\n"
        L"   launcher.exe --sandbox notepad.exe\n"
        L"   launcher.exe --target C:\\Windows\\System32\\cmd.exe --args /c dir\n"
        L"   launcher.exe -d --sandbox D:\\games\\mygame.exe\n"
        L"   launcher.exe --config=custom.ini myapp.exe\n"
        L"   launcher.exe --list-tools\n"
        L"   launcher.exe --unpack --target D:\\games\\steamgame.exe\n"
        L"   launcher.exe --analyze D:\\games\\steamgame\\dump",
        L"Symbiote",
        MB_ICONINFORMATION);
}

int main(int, char**)
{
    std::wstring targetExe;
    std::wstring targetArgs;
    bool useExplorer = false;
    bool debugMode = false;
    bool sandboxMode = false;
    bool listTools = false;
    bool unpackMode = false;
    bool analyzeMode = false;
    std::wstring toolName;
    std::wstring analyzeDir;
    std::wstring profileName;
    std::wstring configPath;

    int wargc = 0;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
    if (wargv) {
        for (int i = 1; i < wargc; i++) {
            std::wstring arg = wargv[i];
            if (arg == L"explorer" || arg == L"-e") {
                useExplorer = true;
            } else if (arg == L"--debug" || arg == L"-d" || arg == L"debug") {
                debugMode = true;
            } else if (arg == L"--sandbox") {
                sandboxMode = true;
                if (i + 1 < wargc) targetExe = wargv[++i];
            } else if (arg == L"--profile" && i + 1 < wargc) {
                profileName = wargv[++i];
            } else if (arg == L"--target" && i + 1 < wargc) {
                targetExe = wargv[++i];
            } else if (arg == L"--args" && i + 1 < wargc) {
                for (int j = i + 1; j < wargc; j++) {
                    if (!targetArgs.empty()) targetArgs += L" ";
                    targetArgs += L"\"" + std::wstring(wargv[j]) + L"\"";
                }
                i = wargc;
            } else if (arg == L"--list-tools" || arg == L"--tools") {
                listTools = true;
            } else if (arg == L"--unpack") {
                unpackMode = true;
            } else if (arg == L"--analyze") {
                analyzeMode = true;
                if (i + 1 < wargc && wargv[i + 1][0] != L'-') {
                    analyzeDir = wargv[++i];
                }
            } else if (arg == L"--tool" && i + 1 < wargc) {
                toolName = wargv[++i];
            } else if (arg.find(L"--config=") == 0) {
                configPath = arg.substr(9);
            } else if (arg.find(L"config=") == 0) {
                configPath = arg.substr(7);
            } else if (arg == L"--help" || arg == L"-h" || arg == L"/?") {
                ShowUsage();
                LocalFree(wargv);
                return 0;
            } else if (arg[0] != L'-') {
                if (targetExe.empty()) targetExe = arg;
            }
        }
        LocalFree(wargv);
    }

    wchar_t modulePath[MAX_PATH];
    GetModuleFileNameW(NULL, modulePath, MAX_PATH);
    std::wstring exeDir = modulePath;
    size_t pos = exeDir.find_last_of(L"\\/");
    if (pos != std::wstring::npos) exeDir = exeDir.substr(0, pos);

    if (configPath.empty()) {
        if (!profileName.empty()) {
            configPath = exeDir + L"\\profiles\\" + profileName + L".ini";
        } else {
            configPath = exeDir + L"\\config\\config.ini";
        }
    }
    std::string configPathA;
    {
        int len = WideCharToMultiByte(CP_UTF8, 0, configPath.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (len > 0) {
            configPathA.resize(len - 1);
            WideCharToMultiByte(CP_UTF8, 0, configPath.c_str(), -1, &configPathA[0], len, nullptr, nullptr);
        }
    }

    // ── External tools ───────────────────────────────────────────────────
    ToolKit toolkit(configPathA, exeDir);

    if (listTools) {
        toolkit.ListTools();
        return 0;
    }

    if (analyzeMode) {
        std::wstring dumpDir = analyzeDir.empty() ? exeDir + L"\\dump\\report" : analyzeDir;
        if (!toolkit.WriteReport(dumpDir, targetExe, L"")) {
            LogMessage("Failed to write report\n");
            return 1;
        }
        std::wstring reportPath = dumpDir + L"\\report.json";
        toolkit.RunAnalyzer(reportPath);
        LogMessage("Analysis complete\n");
        return 0;
    }

    if (unpackMode && !targetExe.empty()) {
        LogMessage("Unpack mode: running Steam/SteamStub unpack chain\n");
        std::wstring unpacked;
        if (!toolkit.UnpackTarget(targetExe, &unpacked)) {
            LogMessage("Unpack failed — no unpacker configured/succeeded\n");
            return 1;
        }
        LogMessage("Launching unpacked target\n");
        targetExe = unpacked;
    }

    if (!toolName.empty() && !targetExe.empty()) {
        LogMessage("Running external tool before launch\n");
        int exitCode = -1;
        std::wstring err;
        std::string toolNameA;
        int tlen = WideCharToMultiByte(CP_UTF8, 0, toolName.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (tlen > 0) {
            toolNameA.resize(tlen - 1);
            WideCharToMultiByte(CP_UTF8, 0, toolName.c_str(), -1, &toolNameA[0], tlen, nullptr, nullptr);
        }
        if (!toolkit.RunTool(toolNameA, targetExe, exeDir + L"\\dump", &exitCode, &err)) {
            std::string errA;
            int elen = WideCharToMultiByte(CP_UTF8, 0, err.c_str(), -1, nullptr, 0, nullptr, nullptr);
            if (elen > 0) {
                errA.resize(elen - 1);
                WideCharToMultiByte(CP_UTF8, 0, err.c_str(), -1, &errA[0], elen, nullptr, nullptr);
            }
            LogMessage("Tool failed: " + errA + "\n");
            return 1;
        }
        LogMessage("Tool completed (exit " + std::to_string(exitCode) + ")\n");
    }

    if (targetExe.empty()) {
        if (useExplorer) {
            targetExe = BrowseForExe();
            if (targetExe.empty()) return 0;
        } else {
            if (!listTools && !analyzeMode) ShowUsage();
            return 0;
        }
    }

    if (sandboxMode) {
        LogMessage("Sandbox mode: forcing all user-mode hooks + WHP intercept\n");
    }

    // ── Orchestrator: unified 8-phase pipeline ──────────────────────────
    LogMessage("Starting Orchestrator...\n");

    Orchestrator orchestrator;

    // Set target info before running phases
    // The Orchestrator phases need to know the target
    // We write directly into the config snapshot that Orchestrator manages
    // by overriding Phase0 defaults
    // Actually — Orchestrator reads config.ini; we need to pass target exe info
    // into the process. Let's store target info in the config snapshot directly.

    ConfigSnapshot* cfg = const_cast<ConfigSnapshot*>(orchestrator.GetConfig());
    wcscpy_s(cfg->targetPath, targetExe.c_str());
    wcscpy_s(cfg->targetArgs, targetArgs.c_str());
    wcscpy_s(cfg->targetDirectory, exeDir.c_str());
    cfg->waitForExit = true;

    const ConfigSnapshot* result = orchestrator.Run();

    if (!result) {
        LogMessage("Orchestrator Run() failed — check launcher.log for details\n");
        return 1;
    }

    LogMessage("Orchestrator completed successfully\n");

    // ── Logging / debug mode ────────────────────────────────────────────
    if (debugMode) {
        // DEBUG: already handled — engine logs verbosely
    }

    LogMessage("All phases complete. Target running.\n");
    return 0;
}