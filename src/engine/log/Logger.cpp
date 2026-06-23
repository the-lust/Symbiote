#include "Logger.h"
#include <cstdarg>
#include <ctime>
#include <iomanip>
#include <sstream>

static const char* CategoryToString(LogCategory cat) {
    switch (cat) {
        case LOG_INFO: return "INFO";
        case LOG_WARNING: return "WARN";
        case LOG_ERROR: return "ERR";
        case LOG_WHP: return "WHP";
        case LOG_EMU: return "EMU";
        case LOG_PROXY: return "PROXY";
        case LOG_EPT: return "EPT";
        case LOG_CPUID: return "CPUID";
        case LOG_TIMING: return "TIMING";
        default: return "??";
    }
}

Logger::Logger()
    : m_file(nullptr), m_initialized(false), m_verbose(false)
{
    InitializeCriticalSection(&m_cs);
}

Logger::~Logger()
{
    if (m_file) fclose(m_file);
    DeleteCriticalSection(&m_cs);
}

bool Logger::Init(const std::wstring& logPath)
{
    EnterCriticalSection(&m_cs);

    std::wstring path = logPath;
    if (path.empty()) {
        wchar_t buf[MAX_PATH];
        GetModuleFileNameW(NULL, buf, MAX_PATH);
        std::wstring exePath = buf;
        size_t pos = exePath.find_last_of(L"\\/");
        if (pos != std::wstring::npos) exePath = exePath.substr(0, pos);
        path = exePath + L"\\whp.log";
    }

    m_file = _wfopen(path.c_str(), L"a+");
    if (!m_file) {
        m_file = _wfopen(path.c_str(), L"w");
    }
    m_initialized = (m_file != nullptr);

    LeaveCriticalSection(&m_cs);
    return m_initialized;
}

void Logger::SetVerbose(bool verbose)
{
    m_verbose = verbose;
}

void Logger::Trace(LogCategory cat, const char* fmt, ...)
{
    if (!m_initialized && !m_file) return;

    char buf[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    std::string entry = std::string("[") + CategoryToString(cat) + "] " + buf;
    Log(entry);
}

void Logger::Log(const std::string& msg)
{
    if (!m_initialized && !m_file) return;
    WriteLog(msg);
}

void Logger::WriteLog(const std::string& entry)
{
    EnterCriticalSection(&m_cs);

    time_t now = time(nullptr);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);
    char timeBuf[64];
    strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", &timeinfo);

    char fullEntry[4224];
    int len = snprintf(fullEntry, sizeof(fullEntry), "[%s] %s\n", timeBuf, entry.c_str());

    if (m_file) {
        fwrite(fullEntry, 1, len, m_file);
        fflush(m_file);
    }

    if (m_verbose) {
        OutputDebugStringA(fullEntry);
        DWORD written;
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hStdout && hStdout != INVALID_HANDLE_VALUE) {
            WriteFile(hStdout, fullEntry, (DWORD)len, &written, NULL);
        }
    }

    LeaveCriticalSection(&m_cs);
}
