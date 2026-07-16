#include "StorageProfile.h"
#include "ConfigParser.h"

StorageProfile::StorageProfile()
    : m_totalSize(512ULL * 1024 * 1024 * 1024), // 512 GB
      m_freeSize(256ULL * 1024 * 1024 * 1024),
      m_model("Samsung SSD 980 PRO 512GB"),
      m_serial("S4P2NJ0T123456")
{
}

StorageProfile::~StorageProfile()
{
}

void StorageProfile::LoadFromConfig(ConfigParser* config)
{
    if (!config) return;

    m_totalSize = config->GetUint64("storage", "total_size", m_totalSize);
    m_freeSize = config->GetUint64("storage", "free_size", m_freeSize);
    m_model = config->GetString("storage", "model",
        config->GetString("hardware", "product", m_model).c_str());
    m_serial = config->GetString("storage", "serial",
        config->GetString("hardware", "serial", m_serial).c_str());
}
