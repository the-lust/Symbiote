#pragma once
#include <windows.h>
#include <cstdio>
#include <string>

enum LogCategory {
    LOG_INFO = 0,
    LOG_WARNING = 1,
    LOG_ERROR = 2,
    LOG_WHP = 3,
    LOG_SOGEN = 4,
    LOG_PROXY = 5,
    LOG_EPT = 6,
    LOG_CPUID = 7,
    LOG_TIMING = 8,
};

class Logger {
public:
    Logger();
    ~Logger();

    bool Init(const std::wstring& logPath = L"");
    void Trace(LogCategory cat, const char* fmt, ...);
    void Log(const std::string& msg);
    void SetVerbose(bool verbose);

private:
    void WriteLog(const std::string& entry);
    FILE* m_file;
    CRITICAL_SECTION m_cs;
    bool m_initialized;
    bool m_verbose;
};
