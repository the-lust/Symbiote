#pragma once
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <fstream>

struct SystemValue {
    std::string category;
    std::string description;
    std::string addr;
    uint64_t value;
    std::string detail;
};

class ResultLogger {
public:
    ResultLogger();
    ~ResultLogger();

    void BeginSection(const std::string& name);
    void EndSection();

    void LogValue(const std::string& category, const std::string& desc,
                  const std::string& addr, uint64_t value,
                  const std::string& detail = "");

    void LogRaw(const std::string& line);
    void FlushToFile(const std::string& path);

private:
    std::vector<SystemValue> m_values;
    std::vector<std::string> m_rawLines;
    std::string m_currentSection;
};
