#pragma once
#include <cstdint>
#include <string>

class StorageProfile {
public:
    StorageProfile();
    ~StorageProfile();

    void LoadFromConfig(class ConfigParser* config = nullptr);

    uint64_t GetTotalSize() const { return m_totalSize; }
    uint64_t GetFreeSize() const { return m_freeSize; }
    std::string GetModel() const { return m_model; }
    std::string GetSerial() const { return m_serial; }

    void SetTotalSize(uint64_t size) { m_totalSize = size; }
    void SetFreeSize(uint64_t size) { m_freeSize = size; }
    void SetModel(const std::string& model) { m_model = model; }
    void SetSerial(const std::string& serial) { m_serial = serial; }

private:
    uint64_t m_totalSize;
    uint64_t m_freeSize;
    std::string m_model;
    std::string m_serial;
};
