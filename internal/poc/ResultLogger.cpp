#include "ResultLogger.h"
#include <iomanip>
#include <sstream>

ResultLogger::ResultLogger() {}
ResultLogger::~ResultLogger() {}

void ResultLogger::BeginSection(const std::string& name)
{
    m_currentSection = name;
    std::string sep = std::string(68, '=');
    m_rawLines.push_back("");
    m_rawLines.push_back(sep);
    m_rawLines.push_back("  " + name);
    m_rawLines.push_back(sep);
    printf("\n\x1b[36m=== %s ===\x1b[0m\n", name.c_str());
}

void ResultLogger::EndSection()
{
    m_rawLines.push_back("");
    printf("\n");
}

void ResultLogger::LogValue(const std::string& category, const std::string& desc,
                             const std::string& addr, uint64_t value,
                             const std::string& detail)
{
    SystemValue v;
    v.category = category;
    v.description = desc;
    v.addr = addr;
    v.value = value;
    v.detail = detail;
    m_values.push_back(v);

    std::stringstream ss;
    ss << "  " << category << " | " << desc;
    if (!addr.empty()) ss << " @ " << addr;
    ss << "\n      value=0x" << std::hex << value;
    if (!detail.empty()) ss << " " << detail;

    std::string line = ss.str();
    m_rawLines.push_back(line);
    printf("%s\n", line.c_str());
}

void ResultLogger::LogRaw(const std::string& line)
{
    m_rawLines.push_back(line);
    printf("%s\n", line.c_str());
}

void ResultLogger::FlushToFile(const std::string& path)
{
    std::ofstream f(path);
    if (!f) return;

    time_t t = time(nullptr);
    struct tm local;
    localtime_s(&local, &t);

    f << "# System Fingerprint Dump\n";
    f << "## Generated: " << std::put_time(&local, "%Y-%m-%d %H:%M:%S") << "\n\n";

    f << "| Check | Description | Address | Value | Detail |\n";
    f << "|---|---|---|---|---|\n";

    for (auto& v : m_values) {
        std::stringstream ss;
        ss << "0x" << std::hex << v.value;
        std::string valStr = ss.str();
        f << "| " << v.category << " | " << v.description
          << " | " << v.addr << " | " << valStr << " | " << v.detail << " |\n";
    }

    f << "\n---\n\n";
    f << "## Full Log\n\n";
    for (auto& l : m_rawLines) {
        std::string clean;
        for (size_t i = 0; i < l.size(); i++) {
            if (l[i] == '\x1b') {
                while (i < l.size() && l[i] != 'm') i++;
                continue;
            }
            clean += l[i];
        }
        f << clean << "\n";
    }

    printf("\n\x1b[36mResults written to %s\x1b[0m\n", path.c_str());
}
