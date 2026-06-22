#pragma once
#include <string>
#include <unordered_map>

class ConfigParser {
public:
    explicit ConfigParser(const std::string& path);
    bool Load();

    std::string GetString(const std::string& section, const std::string& key, const std::string& defaultVal = "") const;
    int GetInt(const std::string& section, const std::string& key, int defaultVal = 0) const;
    uint64_t GetUint64(const std::string& section, const std::string& key, uint64_t defaultVal = 0) const;
    bool GetBool(const std::string& section, const std::string& key, bool defaultVal = false) const;

private:
    std::string m_filePath;
    std::unordered_map<std::string, std::string> m_values;
};
