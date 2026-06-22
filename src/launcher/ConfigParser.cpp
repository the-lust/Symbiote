#include "ConfigParser.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

static std::string Trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    size_t end = s.find_last_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    return s.substr(start, end - start + 1);
}

ConfigParser::ConfigParser(const std::string& path)
    : m_filePath(path)
{
}

bool ConfigParser::Load()
{
    std::ifstream file(m_filePath);
    if (!file.is_open()) return false;

    std::string line;
    std::string currentSection;

    while (std::getline(file, line)) {
        line = Trim(line);
        if (line.empty() || line[0] == ';' || line[0] == '#') continue;

        if (line[0] == '[') {
            size_t end = line.find(']');
            if (end != std::string::npos) {
                currentSection = line.substr(1, end - 1);
            }
            continue;
        }

        size_t eqPos = line.find('=');
        if (eqPos == std::string::npos) continue;

        std::string key = Trim(line.substr(0, eqPos));
        std::string value = Trim(line.substr(eqPos + 1));

        m_values[currentSection + "." + key] = value;
    }

    return true;
}

std::string ConfigParser::GetString(const std::string& section, const std::string& key, const std::string& defaultVal) const
{
    auto it = m_values.find(section + "." + key);
    if (it != m_values.end()) return it->second;
    return defaultVal;
}

int ConfigParser::GetInt(const std::string& section, const std::string& key, int defaultVal) const
{
    auto it = m_values.find(section + "." + key);
    if (it != m_values.end()) {
        try {
            if (it->second.find("0x") == 0 || it->second.find("0X") == 0) {
                return std::stoi(it->second, nullptr, 16);
            }
            return std::stoi(it->second);
        } catch (...) {
            return defaultVal;
        }
    }
    return defaultVal;
}

uint64_t ConfigParser::GetUint64(const std::string& section, const std::string& key, uint64_t defaultVal) const
{
    auto it = m_values.find(section + "." + key);
    if (it != m_values.end()) {
        try {
            if (it->second.find("0x") == 0 || it->second.find("0X") == 0) {
                return std::stoull(it->second, nullptr, 16);
            }
            return std::stoull(it->second);
        } catch (...) {
            return defaultVal;
        }
    }
    return defaultVal;
}

bool ConfigParser::GetBool(const std::string& section, const std::string& key, bool defaultVal) const
{
    auto it = m_values.find(section + "." + key);
    if (it != m_values.end()) {
        std::string val = it->second;
        std::transform(val.begin(), val.end(), val.begin(), ::tolower);
        if (val == "true" || val == "1" || val == "yes" || val == "on") return true;
        if (val == "false" || val == "0" || val == "no" || val == "off") return false;
        return defaultVal;
    }
    return defaultVal;
}
