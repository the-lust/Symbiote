#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdint>
#include <thread>
#include <atomic>
#include "Logger.h"
#include "PacketBuffer.h"

class ICpuBackend;

class GdbStub {
public:
    GdbStub(Logger* logger, ICpuBackend* backend);
    ~GdbStub();

    bool Start(int port = 1234);
    void Stop();
    bool IsConnected() const { return m_connected; }
    void OnStop(uint8_t signal, uint64_t addr);
    ICpuBackend* GetBackend() { return m_backend; }

private:
    Logger* m_logger;
    ICpuBackend* m_backend;
    SOCKET m_listenSocket;
    SOCKET m_clientSocket;
    std::thread m_acceptThread;
    std::thread m_commandThread;
    std::atomic<bool> m_running;
    std::atomic<bool> m_connected;
    std::atomic<bool> m_stopped;
    int m_port;
    CRITICAL_SECTION m_sendLock;

    bool InitWinsock();
    void AcceptLoop();
    void CommandLoop();
    bool SendPacket(const PacketBuffer& pkt);
    bool SendPacketRaw(const uint8_t* data, size_t len);
    bool ReceivePacket(PacketBuffer& pkt, int timeoutMs = 5000);
    bool SendSignal(uint8_t signal);
    void HandleCommand(const PacketBuffer& cmd);
    void HandleQuery(const PacketBuffer& cmd);
    void HandleSetThread(const PacketBuffer& cmd);

    void CmdReadRegisters(PacketBuffer& reply);
    void CmdWriteRegisters(const PacketBuffer& cmd);
    void CmdReadMemory(const PacketBuffer& cmd, PacketBuffer& reply);
    void CmdWriteMemory(const PacketBuffer& cmd);
    void CmdContinue();
    void CmdSingleStep();
    void CmdSetBreakpoint(const PacketBuffer& cmd, bool insert);
    void CmdGetSignal(PacketBuffer& reply);
};
