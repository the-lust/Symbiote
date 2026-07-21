#include <windows.h>
#include <shellapi.h>
#include <commdlg.h>
#include <iostream>
#include <string>
#include <vector>
#include "ConfigParser.h"
#include "WhpDetection.h"
#include "ProcessUtils.h"

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
        L"   config=<path>             Path to config.ini (default: ./config/config.ini)\n\n"
        L"Examples:\n"
        L"   launcher.exe explorer\n"
        L"   launcher.exe --sandbox notepad.exe\n"
        L"   launcher.exe --target C:\\Windows\\System32\\cmd.exe --args /c dir\n"
        L"   launcher.exe -d --sandbox D:\\games\\mygame.exe\n"
        L"   launcher.exe --config=custom.ini myapp.exe",
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
    std::wstring profileName;

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
                if (i + 1 < wargc) {
                    targetExe = wargv[++i];
                }
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
            } else if (arg.find(L"--config") == 0 || arg.find(L"config=") == 0) {
                i++;
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

    if (targetExe.empty()) {
        if (useExplorer) {
            targetExe = BrowseForExe();
            if (targetExe.empty()) return 0;
        } else {
            ShowUsage();
            return 0;
        }
    }

    if (sandboxMode) {
        LogMessage("Sandbox mode: forcing all user-mode hooks + WHP intercept\n");
    }

    wchar_t modulePath[MAX_PATH];
    GetModuleFileNameW(NULL, modulePath, MAX_PATH);
    std::wstring exeDir = modulePath;
    size_t pos = exeDir.find_last_of(L"\\/");
    if (pos != std::wstring::npos) exeDir = exeDir.substr(0, pos);

    std::wstring configPath;
    if (!profileName.empty()) {
        configPath = exeDir + L"\\profiles\\" + profileName + L".ini";
        std::wstring wmsg = L"Loading profile: " + configPath + L"\n";
        int wlen = WideCharToMultiByte(CP_UTF8, 0, wmsg.c_str(), -1, NULL, 0, NULL, NULL);
        std::string msgA(wlen, 0);
        WideCharToMultiByte(CP_UTF8, 0, wmsg.c_str(), -1, &msgA[0], wlen, NULL, NULL);
        LogMessage(msgA);
    } else {
        configPath = exeDir + L"\\config\\config.ini";
    }
    int len = WideCharToMultiByte(CP_UTF8, 0, configPath.c_str(), -1, NULL, 0, NULL, NULL);
    std::string configPathA(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, configPath.c_str(), -1, &configPathA[0], len, NULL, NULL);
    ConfigParser config(configPathA);
    if (!config.Load()) {
        LogMessage("Failed to load config.ini\n");
        std::wstring msg = L"Failed to load config.ini from " + configPath;
        MessageBoxW(NULL, msg.c_str(), L"Config Error", MB_ICONERROR);
        return 1;
    }
    LogMessage("Config loaded successfully\n");

    if (!IsWHPDetected()) {
        LogMessage("WHP not detected - running in degraded mode (IAT hooks only)\n");
        OutputDebugStringA("WHP not detected - running in degraded mode (IAT hooks only)\n");
    } else {
        LogMessage("WHP detected\n");
    }

    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    if (!CreateSuspendedProcess(targetExe, targetArgs, si, pi)) {
        LogMessage("Failed to create process\n");
        std::wstring msg = L"Failed to create process: " + targetExe;
        MessageBoxW(NULL, msg.c_str(), L"Process Error", MB_ICONERROR);
        return 1;
    }
    LogMessage("Process created suspended\n");

    std::wstring dllPath = exeDir + L"\\engine.dll";
    if (!InjectDll(pi.hProcess, dllPath)) {
        LogMessage("Failed to inject engine DLL\n");
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    LogMessage("Engine DLL injected\n");

    if (debugMode) {
        CallRemoteFunction(pi.hProcess, dllPath, "Engine_SetDebug");
        LogMessage("Debug mode enabled\n");
    }

    LogMessage("Calling Engine_Init...\n");
    bool initOk = CallRemoteFunction(pi.hProcess, dllPath, "Engine_Init");
    LogMessage(std::string("Engine_Init: ") + (initOk ? "OK" : "FAILED") + "\n");

    if (initOk && sandboxMode) {
        LogMessage("Setting sandbox mode flag...\n");
        CallRemoteFunction(pi.hProcess, dllPath, "Engine_SetSandboxMode");
        LogMessage("Sandbox mode flag set\n");
    }

    HANDLE hEngineReady = OpenEventW(EVENT_ALL_ACCESS, FALSE, L"Symbiote_EngineReady");
    if (hEngineReady) {
        WaitForSingleObject(hEngineReady, 5000);
        CloseHandle(hEngineReady);
    } else {
        Sleep(750);
    }

    LogMessage("Calling Engine_InterceptEntryPoint...\n");
    CallRemoteFunction(pi.hProcess, dllPath, "Engine_InterceptEntryPoint");
    LogMessage("Engine_InterceptEntryPoint done\n");

    DWORD exitCode = 0;
    ResumeAndWait(pi.hProcess, pi.hThread, &exitCode);
    LogMessage("Process exited\n");

    return (int)exitCode;
}
