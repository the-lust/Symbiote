#pragma once
#include <windows.h>
#include <cstdint>
#include <vector>
#include <string>
#include <fstream>
#include <unordered_map>
#include "Logger.h"

enum class ReplayRecordType : uint8_t {
    CPUID = 0,
    RDTSC = 1,
    MSR_READ = 2,
    SYSCALL_RESULT = 3,
    TIMER = 4,
    INTERRUPT = 5,
    IO_READ = 6,
    MEMORY_READ = 7,
    SETUP = 0xFF
};

struct ReplayEntry {
    ReplayRecordType type;
    uint64_t sequenceNumber;
    uint64_t inputKey;
    uint64_t outputValue;
    uint32_t cpuIndex;
    uint32_t dataSize;
    std::vector<uint8_t> data;
};

class ReplayLogger {
public:
    explicit ReplayLogger(Logger* logger);
    ~ReplayLogger();

    bool BeginRecord(const std::string& filePath);
    bool BeginReplay(const std::string& filePath);
    void Close();

    bool IsRecording() const { return m_recording; }
    bool IsReplaying() const { return m_replaying; }
    uint64_t GetReplayLength() const { return m_totalEntries; }

    void RecordInput(ReplayRecordType type, uint64_t inputKey, uint64_t outputValue, uint32_t cpuIndex = 0);
    void RecordInputWithData(ReplayRecordType type, uint64_t inputKey, const uint8_t* data, uint32_t dataSize, uint32_t cpuIndex = 0);

    uint64_t ReplayNext(ReplayRecordType& outType, uint64_t& outInputKey, uint32_t& outDataSize, const uint8_t*& outData);
    bool SeekTo(uint64_t sequenceNumber);
    uint64_t GetNextSequence() const { return m_nextSequence; }
    uint64_t GetCurrentPosition() const { return m_currentEntry; }

private:
    Logger* m_logger;
    bool m_recording;
    bool m_replaying;
    std::string m_filePath;
    std::ofstream m_outFile;
    std::ifstream m_inFile;
    uint64_t m_nextSequence;
    uint64_t m_currentEntry;
    uint64_t m_totalEntries;
    std::vector<ReplayEntry> m_replayBuffer;
    size_t m_replayIndex;
    CRITICAL_SECTION m_lock;

    void WriteEntry(const ReplayEntry& entry);
    bool ReadEntry(ReplayEntry& entry);
};
