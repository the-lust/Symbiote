#include "GdbStub.h"
#include "PacketBuffer.h"
#include "backend/ICpuBackend.h"
#pragma comment(lib, "ws2_32.lib")

GdbStub::GdbStub(Logger* logger, ICpuBackend* backend)
    : m_logger(logger)
    , m_backend(backend)
    , m_listenSocket(INVALID_SOCKET)
    , m_clientSocket(INVALID_SOCKET)
    , m_running(false)
    , m_connected(false)
    , m_stopped(false)
    , m_port(1234)
{
    InitializeCriticalSection(&m_sendLock);
}

GdbStub::~GdbStub()
{
    Stop();
    DeleteCriticalSection(&m_sendLock);
}

bool GdbStub::Start(int port)
{
    m_port = port;
    if (!InitWinsock()) return false;

    m_listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_listenSocket == INVALID_SOCKET) return false;

    int opt = 1;
    setsockopt(m_listenSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((u_short)port);

    if (bind(m_listenSocket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(m_listenSocket);
        m_listenSocket = INVALID_SOCKET;
        return false;
    }

    listen(m_listenSocket, 1);
    m_running = true;
    m_acceptThread = std::thread(&GdbStub::AcceptLoop, this);
    m_logger->Trace(LOG_INFO, "GDB stub listening on port %d", port);
    return true;
}

void GdbStub::Stop()
{
    m_running = false;
    if (m_clientSocket != INVALID_SOCKET) {
        closesocket(m_clientSocket);
        m_clientSocket = INVALID_SOCKET;
    }
    if (m_listenSocket != INVALID_SOCKET) {
        closesocket(m_listenSocket);
        m_listenSocket = INVALID_SOCKET;
    }
    if (m_acceptThread.joinable()) m_acceptThread.join();
    if (m_commandThread.joinable()) m_commandThread.join();
    m_connected = false;
}

bool GdbStub::InitWinsock()
{
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
}

void GdbStub::AcceptLoop()
{
    while (m_running) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(m_listenSocket, &readSet);
        timeval tv = { 1, 0 };
        int ret = select(0, &readSet, nullptr, nullptr, &tv);
        if (ret <= 0) continue;

        sockaddr_in clientAddr;
        int addrLen = sizeof(clientAddr);
        m_clientSocket = accept(m_listenSocket, (sockaddr*)&clientAddr, &addrLen);
        if (m_clientSocket == INVALID_SOCKET) continue;

        m_logger->Trace(LOG_INFO, "GDB client connected");
        m_connected = true;
        m_stopped = true;

        if (m_commandThread.joinable()) m_commandThread.join();
        m_commandThread = std::thread(&GdbStub::CommandLoop, this);
    }
}

void GdbStub::CommandLoop()
{
    SendSignal(5);

    PacketBuffer pkt;
    while (m_connected && m_running) {
        if (!ReceivePacket(pkt, 5000)) {
            if (m_running) continue;
            break;
        }

        char ack = '+';
        if (m_clientSocket != INVALID_SOCKET)
            send(m_clientSocket, &ack, 1, 0);

        HandleCommand(pkt);
    }

    if (m_clientSocket != INVALID_SOCKET) {
        closesocket(m_clientSocket);
        m_clientSocket = INVALID_SOCKET;
    }
    m_connected = false;
    m_logger->Trace(LOG_INFO, "GDB client disconnected");
}

bool GdbStub::SendPacket(const PacketBuffer& pkt)
{
    const auto& raw = pkt.GetPacket();
    return SendPacketRaw(raw.data(), raw.size());
}

bool GdbStub::SendPacketRaw(const uint8_t* data, size_t len)
{
    if (m_clientSocket == INVALID_SOCKET) return false;
    EnterCriticalSection(&m_sendLock);
    int sent = send(m_clientSocket, (const char*)data, (int)len, 0);
    LeaveCriticalSection(&m_sendLock);
    return sent == (int)len;
}

bool GdbStub::ReceivePacket(PacketBuffer& pkt, int timeoutMs)
{
    std::vector<uint8_t> buf;
    bool inPacket = false;
    auto start = GetTickCount64();

    while (m_connected) {
        if (GetTickCount64() - start > (uint64_t)timeoutMs) return false;

        char c = 0;
        int ret = recv(m_clientSocket, &c, 1, 0);
        if (ret <= 0) {
            if (ret == 0) m_connected = false;
            return false;
        }

        if (c == '$') {
            buf.clear();
            buf.push_back(c);
            inPacket = true;
        } else if (inPacket) {
            buf.push_back(c);
            if (c == '#') {
                char hex[3] = {0, 0, 0};
                ret = recv(m_clientSocket, hex, 2, 0);
                if (ret == 2) {
                    buf.push_back(hex[0]);
                    buf.push_back(hex[1]);
                    return pkt.ParsePacket(buf.data(), buf.size());
                }
                return false;
            }
        }
    }
    return false;
}

bool GdbStub::SendSignal(uint8_t signal)
{
    PacketBuffer pkt;
    pkt.WriteByte('T');
    pkt.WriteHex(&signal, 1);
    pkt.BuildPacket();
    return SendPacket(pkt);
}

void GdbStub::OnStop(uint8_t signal, uint64_t addr)
{
    (void)addr;
    m_stopped = true;
    if (m_connected) {
        SendSignal(signal);
    }
}

void GdbStub::HandleCommand(const PacketBuffer& cmd)
{
    if (cmd.GetSize() == 0) return;
    PacketBuffer reply;
    uint8_t cmdByte = cmd.GetData()[0];

    switch (cmdByte) {
        case '?': CmdGetSignal(reply); break;
        case 'g': CmdReadRegisters(reply); break;
        case 'G': CmdWriteRegisters(cmd); reply.Clear(); reply.WriteString("OK"); break;
        case 'm': CmdReadMemory(cmd, reply); break;
        case 'M': CmdWriteMemory(cmd); reply.Clear(); reply.WriteString("OK"); break;
        case 'c': CmdContinue(); return;
        case 's': CmdSingleStep(); return;
        case 'Z': CmdSetBreakpoint(cmd, true); reply.Clear(); reply.WriteString("OK"); break;
        case 'z': CmdSetBreakpoint(cmd, false); reply.Clear(); reply.WriteString("OK"); break;
        case 'q': HandleQuery(cmd); return;
        case 'H': HandleSetThread(cmd); reply.Clear(); reply.WriteString("OK"); break;
        case 'T': reply.Clear(); reply.WriteString("OK"); break;
        default: reply.Clear(); reply.WriteString(""); break;
    }

    if (reply.GetSize() > 0) {
        reply.BuildPacket();
        SendPacket(reply);
    }
}

void GdbStub::CmdGetSignal(PacketBuffer& reply)
{
    uint8_t sig = 5;
    reply.WriteByte('S');
    reply.WriteHex(&sig, 1);
}

void GdbStub::CmdReadRegisters(PacketBuffer& reply)
{
    for (int i = 0; i < (int)CpuReg::COUNT; i++) {
        uint64_t val = m_backend ? m_backend->ReadRegister((CpuReg)i) : 0;
        reply.WriteHex((uint8_t*)&val, 8);
    }
}

void GdbStub::CmdWriteRegisters(const PacketBuffer& cmd)
{
    PacketBuffer parser = cmd;
    parser.Skip(1);
    for (int i = 0; i < (int)CpuReg::COUNT && parser.HasMore(); i++) {
        uint64_t val = parser.ReadHex(16);
        if (m_backend) m_backend->WriteRegister((CpuReg)i, val);
    }
}

void GdbStub::CmdReadMemory(const PacketBuffer& cmd, PacketBuffer& reply)
{
    PacketBuffer parser = cmd;
    parser.Skip(1);
    uint64_t addr = parser.ReadHex(0);
    parser.Skip(1);
    uint64_t len = parser.ReadHex(0);
    if (addr == 0 || len == 0) return;
    if (len > 4096) len = 4096;

    std::vector<uint8_t> buf((size_t)len);
    if (m_backend && m_backend->ReadMemory(addr, buf.data(), (size_t)len)) {
        reply.WriteHex(buf.data(), (size_t)len);
    }
}

void GdbStub::CmdWriteMemory(const PacketBuffer& cmd)
{
    PacketBuffer parser = cmd;
    parser.Skip(1);
    uint64_t addr = parser.ReadHex(0);
    parser.Skip(1);
    uint64_t len = parser.ReadHex(0);
    parser.Skip(1);
    if (addr == 0 || len == 0) return;

    std::vector<uint8_t> buf((size_t)len);
    for (size_t i = 0; i < (size_t)len && parser.HasMore(); i += 2) {
        uint8_t b = (uint8_t)parser.ReadHex(2);
        buf[i] = b;
    }
    if (m_backend) m_backend->WriteMemory(addr, buf.data(), (size_t)len);
}

void GdbStub::CmdContinue()
{
    m_stopped = false;
    if (m_backend) m_backend->Run();
    uint8_t sig = 5;
    OnStop(sig, m_backend ? m_backend->ReadRegister(CpuReg::RIP) : 0);
}

void GdbStub::CmdSingleStep()
{
    m_stopped = false;
    if (m_backend) m_backend->SingleStep();
    uint8_t sig = 5;
    OnStop(sig, m_backend ? m_backend->ReadRegister(CpuReg::RIP) : 0);
}

void GdbStub::CmdSetBreakpoint(const PacketBuffer& cmd, bool insert)
{
    PacketBuffer parser = cmd;
    parser.Skip(3);
    uint64_t addr = parser.ReadHex(0);
    if (insert) {
        if (m_backend) m_backend->SetBreakpoint(addr);
    } else {
        if (m_backend) m_backend->RemoveBreakpoint(addr);
    }
}

void GdbStub::HandleQuery(const PacketBuffer& cmd)
{
    PacketBuffer reply;

    std::string query((const char*)cmd.GetData() + 1, cmd.GetSize() - 1);
    if (query == "Supported") {
        reply.WriteString("PacketSize=1024;qXfer:features:read+;QStartNoAckMode+");
    } else if (query == "Attached") {
        reply.WriteString("1");
    } else if (query.find("Xfer:features:read:target.xml:") == 0) {
        reply.WriteString("l<?xml version=\"1.0\"?>");
        reply.WriteString("<target><architecture>i386:x86-64</architecture></target>");
    } else {
        return;
    }

    reply.BuildPacket();
    SendPacket(reply);
}

void GdbStub::HandleSetThread(const PacketBuffer& cmd)
{
    (void)cmd;
    PacketBuffer reply;
    reply.WriteString("OK");
    reply.BuildPacket();
    SendPacket(reply);
}
