// Credits: Deterministic record/replay pattern adapted from Sogen (https://github.com/hedronium/Sogen)
#include "ReplayLogger.h"
#include <algorithm>
#include <cstring>

ReplayLogger::ReplayLogger(Logger* logger)
    : m_logger(logger)
    , m_recording(false)
    , m_replaying(false)
    , m_nextSequence(0)
    , m_currentEntry(0)
    , m_totalEntries(0)
    , m_replayIndex(0)
{
    InitializeCriticalSection(&m_lock);
}

ReplayLogger::~ReplayLogger()
{
    Close();
    DeleteCriticalSection(&m_lock);
}

bool ReplayLogger::BeginRecord(const std::string& filePath)
{
    Close();
    m_outFile.open(filePath, std::ios::binary | std::ios::trunc);
    if (!m_outFile) return false;

    ReplayEntry header;
    header.type = ReplayRecordType::SETUP;
    header.sequenceNumber = 0;
    header.inputKey = 0;
    header.outputValue = 0;
    header.cpuIndex = 0;
    header.dataSize = 0;
    WriteEntry(header);

    m_recording = true;
    m_filePath = filePath;
    m_nextSequence = 1;
    m_logger->Trace(LOG_INFO, "ReplayLogger: recording to %s", filePath.c_str());
    return true;
}

bool ReplayLogger::BeginReplay(const std::string& filePath)
{
    Close();
    m_inFile.open(filePath, std::ios::binary);
    if (!m_inFile) return false;

    ReplayEntry header;
    if (!ReadEntry(header) || header.type != ReplayRecordType::SETUP) {
        m_inFile.close();
        return false;
    }

    m_replayBuffer.clear();
    ReplayEntry entry;
    while (ReadEntry(entry)) {
        m_replayBuffer.push_back(std::move(entry));
    }

    m_inFile.close();
    m_replaying = true;
    m_filePath = filePath;
    m_replayIndex = 0;
    m_totalEntries = m_replayBuffer.size();
    m_currentEntry = 0;
    m_logger->Trace(LOG_INFO, "ReplayLogger: replaying %llu entries from %s",
        (uint64_t)m_replayBuffer.size(), filePath.c_str());
    return true;
}

void ReplayLogger::Close()
{
    if (m_outFile.is_open()) m_outFile.close();
    if (m_inFile.is_open()) m_inFile.close();
    m_recording = false;
    m_replaying = false;
    m_replayBuffer.clear();
    m_replayIndex = 0;
    m_totalEntries = 0;
    m_currentEntry = 0;
}

void ReplayLogger::RecordInput(ReplayRecordType type, uint64_t inputKey, uint64_t outputValue, uint32_t cpuIndex)
{
    if (!m_recording) return;
    EnterCriticalSection(&m_lock);

    ReplayEntry entry;
    entry.type = type;
    entry.sequenceNumber = m_nextSequence++;
    entry.inputKey = inputKey;
    entry.outputValue = outputValue;
    entry.cpuIndex = cpuIndex;
    entry.dataSize = 0;
    WriteEntry(entry);

    LeaveCriticalSection(&m_lock);
}

void ReplayLogger::RecordInputWithData(ReplayRecordType type, uint64_t inputKey,
    const uint8_t* data, uint32_t dataSize, uint32_t cpuIndex)
{
    if (!m_recording) return;
    EnterCriticalSection(&m_lock);

    ReplayEntry entry;
    entry.type = type;
    entry.sequenceNumber = m_nextSequence++;
    entry.inputKey = inputKey;
    entry.outputValue = 0;
    entry.cpuIndex = cpuIndex;
    entry.dataSize = dataSize;
    entry.data.assign(data, data + dataSize);
    WriteEntry(entry);

    LeaveCriticalSection(&m_lock);
}

uint64_t ReplayLogger::ReplayNext(ReplayRecordType& outType, uint64_t& outInputKey,
    uint32_t& outDataSize, const uint8_t*& outData)
{
    if (!m_replaying || m_replayIndex >= m_replayBuffer.size()) {
        outType = ReplayRecordType::SETUP;
        outInputKey = 0;
        outDataSize = 0;
        outData = nullptr;
        return 0;
    }

    const auto& entry = m_replayBuffer[m_replayIndex++];
    outType = entry.type;
    outInputKey = entry.inputKey;
    outDataSize = entry.dataSize;
    outData = entry.data.empty() ? nullptr : entry.data.data();
    m_currentEntry = entry.sequenceNumber;
    return entry.outputValue;
}

bool ReplayLogger::SeekTo(uint64_t sequenceNumber)
{
    if (!m_replaying) return false;
    for (size_t i = 0; i < m_replayBuffer.size(); i++) {
        if (m_replayBuffer[i].sequenceNumber == sequenceNumber) {
            m_replayIndex = i;
            m_currentEntry = sequenceNumber;
            return true;
        }
    }
    return false;
}

void ReplayLogger::WriteEntry(const ReplayEntry& entry)
{
    uint32_t typeRaw = (uint32_t)entry.type;
    m_outFile.write((const char*)&typeRaw, sizeof(typeRaw));
    m_outFile.write((const char*)&entry.sequenceNumber, sizeof(entry.sequenceNumber));
    m_outFile.write((const char*)&entry.inputKey, sizeof(entry.inputKey));
    m_outFile.write((const char*)&entry.outputValue, sizeof(entry.outputValue));
    m_outFile.write((const char*)&entry.cpuIndex, sizeof(entry.cpuIndex));
    m_outFile.write((const char*)&entry.dataSize, sizeof(entry.dataSize));
    if (entry.dataSize > 0) {
        m_outFile.write((const char*)entry.data.data(), entry.dataSize);
    }
}

bool ReplayLogger::ReadEntry(ReplayEntry& entry)
{
    uint32_t typeRaw = 0;
    if (!m_inFile.read((char*)&typeRaw, sizeof(typeRaw))) return false;
    if (!m_inFile.read((char*)&entry.sequenceNumber, sizeof(entry.sequenceNumber))) return false;
    if (!m_inFile.read((char*)&entry.inputKey, sizeof(entry.inputKey))) return false;
    if (!m_inFile.read((char*)&entry.outputValue, sizeof(entry.outputValue))) return false;
    if (!m_inFile.read((char*)&entry.cpuIndex, sizeof(entry.cpuIndex))) return false;
    if (!m_inFile.read((char*)&entry.dataSize, sizeof(entry.dataSize))) return false;

    entry.type = (ReplayRecordType)typeRaw;
    entry.data.clear();
    if (entry.dataSize > 0) {
        entry.data.resize(entry.dataSize);
        if (!m_inFile.read((char*)entry.data.data(), entry.dataSize)) return false;
    }
    return true;
}
