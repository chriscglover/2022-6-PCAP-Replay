#include "pcapreplay/net_multicast.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>

#include <atomic>
#include <cstring>

// Not exposed by every Windows SDK header, but the ioctl itself has been
// supported since Windows 2000.
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

namespace pcapreplay {
namespace {

std::atomic<int> g_wsaRefs{0};

constexpr std::uintptr_t kInvalid = ~std::uintptr_t(0);

SOCKET asSocket(std::uintptr_t s) { return SOCKET(s); }

}  // namespace

std::string winsockErrorText(int code) {
    char* msg = nullptr;
    const DWORD n = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, DWORD(code), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<char*>(&msg), 0, nullptr);
    std::string s;
    if (n && msg) {
        s.assign(msg, n);
        while (!s.empty() && (s.back() == '\r' || s.back() == '\n')) s.pop_back();
    } else {
        s = "error " + std::to_string(code);
    }
    if (msg) LocalFree(msg);
    return s + " (" + std::to_string(code) + ")";
}

// ---------------------------------------------------------------------------

WinsockScope::WinsockScope() {
    WSADATA d{};
    ok_ = WSAStartup(MAKEWORD(2, 2), &d) == 0;
    if (ok_) g_wsaRefs.fetch_add(1);
}

WinsockScope::~WinsockScope() {
    if (ok_ && g_wsaRefs.fetch_sub(1) == 1) WSACleanup();
}

// ---------------------------------------------------------------------------

MulticastSender::~MulticastSender() { close(); }

bool MulticastSender::open(const MulticastEndpoint& ep, int ttl, bool loopback,
                           int sendBufferBytes) {
    close();

    in_addr group{};
    if (inet_pton(AF_INET, ep.group.c_str(), &group) != 1) {
        lastError_ = "invalid multicast group '" + ep.group + "'";
        return false;
    }
    if (ep.port == 0) {
        lastError_ = "port must be non-zero";
        return false;
    }

    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        lastError_ = "socket: " + winsockErrorText(WSAGetLastError());
        return false;
    }

    // Choose the outgoing interface explicitly -- the whole point of the
    // per-path NIC selector.
    if (!ep.interfaceIp.empty()) {
        in_addr ifAddr{};
        if (inet_pton(AF_INET, ep.interfaceIp.c_str(), &ifAddr) != 1) {
            lastError_ = "invalid interface address '" + ep.interfaceIp + "'";
            closesocket(s);
            return false;
        }
        if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF,
                       reinterpret_cast<const char*>(&ifAddr), sizeof ifAddr) != 0) {
            lastError_ = "IP_MULTICAST_IF: " + winsockErrorText(WSAGetLastError());
            closesocket(s);
            return false;
        }
    }

    const DWORD ttlV = DWORD(ttl);
    setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL,
               reinterpret_cast<const char*>(&ttlV), sizeof ttlV);

    const DWORD loopV = loopback ? 1 : 0;
    setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP,
               reinterpret_cast<const char*>(&loopV), sizeof loopV);

    // A generous send buffer stops sendto() blocking on a burst; too small and
    // the pacer's careful spacing is destroyed by backpressure.
    const int snd = sendBufferBytes;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF,
               reinterpret_cast<const char*>(&snd), sizeof snd);

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(ep.port);
    dst.sin_addr = group;
    dstAddr_.resize(sizeof dst);
    std::memcpy(dstAddr_.data(), &dst, sizeof dst);

    sock_ = std::uintptr_t(s);
    lastError_.clear();
    sent_ = errors_ = 0;
    return true;
}

void MulticastSender::close() {
    if (sock_ != kInvalid) {
        closesocket(asSocket(sock_));
        sock_ = kInvalid;
    }
    dstAddr_.clear();
}

int MulticastSender::send(std::span<const std::uint8_t> datagram) {
    if (sock_ == kInvalid || dstAddr_.empty()) return -1;
    const int n = sendto(
        asSocket(sock_),
        reinterpret_cast<const char*>(datagram.data()),
        int(datagram.size()), 0,
        reinterpret_cast<const sockaddr*>(dstAddr_.data()),
        int(dstAddr_.size()));
    if (n < 0) {
        ++errors_;
        lastError_ = "sendto: " + winsockErrorText(WSAGetLastError());
        return -1;
    }
    ++sent_;
    return n;
}

#ifndef UDP_SEND_MSG_SIZE
#define UDP_SEND_MSG_SIZE 2
#endif

bool MulticastSender::enableSegmentation(int segmentBytes) {
    segmentBytes_ = 0;
    if (sock_ == kInvalid || segmentBytes <= 0) return false;

    const DWORD seg = DWORD(segmentBytes);
    if (setsockopt(asSocket(sock_), IPPROTO_UDP, UDP_SEND_MSG_SIZE,
                   reinterpret_cast<const char*>(&seg), sizeof seg) != 0) {
        lastError_ = "UDP_SEND_MSG_SIZE unsupported: " +
                     winsockErrorText(WSAGetLastError());
        return false;
    }
    segmentBytes_ = segmentBytes;
    return true;
}

int MulticastSender::sendMany(const std::uint8_t* buffer, int segmentBytes, int count) {
    if (sock_ == kInvalid || count <= 0) return -1;

    if (segmentBytes_ == segmentBytes) {
        const int total = segmentBytes * count;
        const int n = sendto(
            asSocket(sock_), reinterpret_cast<const char*>(buffer), total, 0,
            reinterpret_cast<const sockaddr*>(dstAddr_.data()), int(dstAddr_.size()));
        if (n < 0) {
            ++errors_;
            lastError_ = "sendto(segmented): " + winsockErrorText(WSAGetLastError());
            return -1;
        }
        sent_ += std::uint64_t(count);
        return count;
    }

    // Fallback: one syscall per datagram.
    int done = 0;
    for (int i = 0; i < count; ++i) {
        if (send({buffer + std::size_t(i) * segmentBytes, std::size_t(segmentBytes)}) < 0)
            break;
        ++done;
    }
    return done;
}

// ---------------------------------------------------------------------------

MulticastReceiver::~MulticastReceiver() { close(); }

bool MulticastReceiver::open(const MulticastEndpoint& ep, int recvBufferBytes) {
    close();

    in_addr group{};
    if (inet_pton(AF_INET, ep.group.c_str(), &group) != 1) {
        lastError_ = "invalid multicast group '" + ep.group + "'";
        return false;
    }

    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        lastError_ = "socket: " + winsockErrorText(WSAGetLastError());
        return false;
    }

    // Disable SIO_UDP_CONNRESET.
    //
    // Windows puts a UDP socket into a permanent error state if any datagram it
    // sent elicits an ICMP Port Unreachable: every later recv() then fails with
    // WSAECONNRESET forever. On a receive-only multicast socket this is pure
    // sabotage -- the stream stops dead while the IGMP membership stays valid,
    // so the switch and bridge both still show us subscribed and everything
    // upstream looks perfect. Recovers only on socket recreate.
    {
        BOOL behaviour = FALSE;
        DWORD returned = 0;
        WSAIoctl(s, SIO_UDP_CONNRESET, &behaviour, sizeof behaviour,
                 nullptr, 0, &returned, nullptr, nullptr);
    }

    // Share the group with other listeners on this machine.
    const DWORD reuse = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&reuse), sizeof reuse);

    // Bind to the port on any address; the group membership does the filtering.
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = htons(ep.port);
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(s, reinterpret_cast<const sockaddr*>(&local), sizeof local) != 0) {
        lastError_ = "bind: " + winsockErrorText(WSAGetLastError());
        closesocket(s);
        return false;
    }

    // A large receive buffer is essential: 1.485 Gb/s leaves very little time
    // to drain, and a short stall becomes packet loss the -7 merge then has to
    // paper over.
    const int rcv = recvBufferBytes;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF,
               reinterpret_cast<const char*>(&rcv), sizeof rcv);

    ip_mreq mreq{};
    mreq.imr_multiaddr = group;
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (!ep.interfaceIp.empty()) {
        if (inet_pton(AF_INET, ep.interfaceIp.c_str(), &mreq.imr_interface) != 1) {
            lastError_ = "invalid interface address '" + ep.interfaceIp + "'";
            closesocket(s);
            return false;
        }
    }
    if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   reinterpret_cast<const char*>(&mreq), sizeof mreq) != 0) {
        lastError_ = "IP_ADD_MEMBERSHIP: " + winsockErrorText(WSAGetLastError());
        closesocket(s);
        return false;
    }

    mreq_.resize(sizeof mreq);
    std::memcpy(mreq_.data(), &mreq, sizeof mreq);
    joined_ = true;
    sock_ = std::uintptr_t(s);
    lastError_.clear();
    received_ = 0;
    return true;
}

void MulticastReceiver::close() {
    if (sock_ != kInvalid) {
        if (joined_ && mreq_.size() == sizeof(ip_mreq))
            setsockopt(asSocket(sock_), IPPROTO_IP, IP_DROP_MEMBERSHIP,
                       reinterpret_cast<const char*>(mreq_.data()), int(mreq_.size()));
        closesocket(asSocket(sock_));
        sock_ = kInvalid;
    }
    joined_ = false;
    mreq_.clear();
}

bool MulticastReceiver::rejoin() {
    if (sock_ == kInvalid || mreq_.size() != sizeof(ip_mreq)) return false;

    setsockopt(asSocket(sock_), IPPROTO_IP, IP_DROP_MEMBERSHIP,
               reinterpret_cast<const char*>(mreq_.data()), int(mreq_.size()));
    if (setsockopt(asSocket(sock_), IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   reinterpret_cast<const char*>(mreq_.data()), int(mreq_.size())) != 0) {
        lastError_ = "re-join failed: " + winsockErrorText(WSAGetLastError());
        joined_ = false;
        return false;
    }
    joined_ = true;
    ++rejoins_;
    return true;
}

int MulticastReceiver::receive(std::span<std::uint8_t> buffer, int timeoutMs) {
    if (sock_ == kInvalid) return -1;

    if (timeoutMs != timeoutMs_) {
        const DWORD to = DWORD(timeoutMs);
        setsockopt(asSocket(sock_), SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&to), sizeof to);
        timeoutMs_ = timeoutMs;
    }

    const int n = recv(asSocket(sock_),
                       reinterpret_cast<char*>(buffer.data()),
                       int(buffer.size()), 0);
    if (n < 0) {
        const int e = WSAGetLastError();
        if (e == WSAETIMEDOUT) return 0;
        lastError_ = "recv: " + winsockErrorText(e);
        return -1;
    }
    ++received_;
    return n;
}

int MulticastReceiver::receiveBatch(std::uint8_t* buffer, std::size_t stride,
                                    int* lengths, int maxDatagrams, int timeoutMs) {
    if (sock_ == kInvalid || maxDatagrams <= 0) return -1;

    // First read blocks up to the timeout; the rest are drained non-blocking so
    // a burst is collected in one go.
    int count = 0;
    const int n0 = receive({buffer, stride}, timeoutMs);
    if (n0 < 0) return -1;
    if (n0 == 0) return 0;
    lengths[count++] = n0;

    u_long nonBlocking = 1;
    ioctlsocket(asSocket(sock_), FIONBIO, &nonBlocking);
    while (count < maxDatagrams) {
        const int n = recv(asSocket(sock_),
                           reinterpret_cast<char*>(buffer + std::size_t(count) * stride),
                           int(stride), 0);
        if (n <= 0) break;
        lengths[count++] = n;
        ++received_;
    }
    nonBlocking = 0;
    ioctlsocket(asSocket(sock_), FIONBIO, &nonBlocking);

    return count;
}

}  // namespace pcapreplay
