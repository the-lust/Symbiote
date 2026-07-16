#pragma once
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

class PacketBuffer {
public:
    PacketBuffer() : m_pos(0) {}

    void Clear() { m_data.clear(); m_pos = 0; }
    void WriteByte(uint8_t b) { m_data.push_back(b); }
    void WriteBytes(const uint8_t* buf, size_t len) { m_data.insert(m_data.end(), buf, buf + len); }
    void WriteHex(const uint8_t* buf, size_t len) {
        static const char hex[] = "0123456789abcdef";
        for (size_t i = 0; i < len; i++) {
            WriteByte(hex[buf[i] >> 4]);
            WriteByte(hex[buf[i] & 0xF]);
        }
    }
    void WriteHex64(uint64_t val) {
        for (int i = 56; i >= 0; i -= 8)
            WriteHex((uint8_t*)&val + (i >> 3), 1);
    }
    void WriteString(const char* s) {
        while (*s) WriteByte(*s++);
    }
    void WriteNumberHex(uint64_t val, int nibbles) {
        static const char hex[] = "0123456789abcdef";
        for (int i = nibbles - 1; i >= 0; i--)
            WriteByte(hex[(val >> (i * 4)) & 0xF]);
    }

    uint8_t ReadByte() { return m_pos < m_data.size() ? m_data[m_pos++] : 0; }
    uint8_t PeekByte() const { return m_pos < m_data.size() ? m_data[m_pos] : 0; }
    uint64_t ReadHex(int nibbles) {
        uint64_t val = 0;
        for (int i = 0; i < nibbles && m_pos < m_data.size(); i++, m_pos++) {
            uint8_t c = m_data[m_pos];
            val <<= 4;
            if (c >= '0' && c <= '9') val |= (c - '0');
            else if (c >= 'a' && c <= 'f') val |= (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') val |= (c - 'A' + 10);
        }
        return val;
    }
    void Skip(int n) { m_pos += n; if (m_pos > (int)m_data.size()) m_pos = (int)m_data.size(); }

    size_t GetSize() const { return m_data.size(); }
    size_t GetPos() const { return m_pos; }
    bool HasMore() const { return m_pos < (int)m_data.size(); }
    const uint8_t* GetData() const { return m_data.data(); }
    size_t remaining() const { return m_data.size() - m_pos; }

    bool BuildPacket() {
        uint8_t checksum = 0;
        for (size_t i = 0; i < m_data.size(); i++)
            checksum += m_data[i];
        m_packet.clear();
        m_packet.push_back('$');
        m_packet.insert(m_packet.end(), m_data.begin(), m_data.end());
        m_packet.push_back('#');
        char hex[3];
        sprintf_s(hex, "%02x", checksum);
        m_packet.push_back(hex[0]);
        m_packet.push_back(hex[1]);
        return true;
    }

    bool ParsePacket(const uint8_t* raw, size_t len) {
        Clear();
        if (len < 4 || raw[0] != '$') return false;
        size_t start = 1;
        size_t end = 0;
        for (size_t i = start; i < len; i++) {
            if (raw[i] == '#') { end = i; break; }
        }
        if (end == 0) return false;
        if (end + 2 >= len) return false;
        uint8_t calc = 0;
        for (size_t i = start; i < end; i++) calc += raw[i];
        char expHex[3] = { (char)raw[end + 1], (char)raw[end + 2], 0 };
        uint8_t expected = (uint8_t)strtoul(expHex, nullptr, 16);
        if (calc != expected) return false;
        m_data.assign(raw + start, raw + end);
        m_pos = 0;
        return true;
    }

    const std::vector<uint8_t>& GetPacket() const { return m_packet; }

private:
    std::vector<uint8_t> m_data;
    std::vector<uint8_t> m_packet;
    int m_pos;
};
