#include "pcapreplay/stats_server.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include "pcapreplay/net_multicast.h"   // winsockErrorText

namespace pcapreplay {
namespace {
constexpr std::uintptr_t kInvalid = ~std::uintptr_t(0);
}

StatsServer::~StatsServer() { stop(); }

bool StatsServer::start(std::uint16_t port, std::function<std::string()> provider,
                        const std::string& bindAddress) {
    stop();
    provider_ = std::move(provider);

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        error_ = "socket: " + winsockErrorText(WSAGetLastError());
        return false;
    }

    // SO_EXCLUSIVEADDRUSE, not SO_REUSEADDR. On Windows SO_REUSEADDR lets a
    // second process bind a port another process is already listening on, and
    // which of them then receives a connection is not defined. That is a port
    // hijack in general, and in practice it meant this app silently answered
    // with another replay tool's statistics. A listening socket does not enter
    // TIME_WAIT, so there is nothing to lose by being exclusive.
    const DWORD exclusive = 1;
    setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
               reinterpret_cast<const char*>(&exclusive), sizeof exclusive);

    // Loopback unless explicitly told otherwise. These apps often run on
    // separate machines and the stats are the whole diagnostic surface, so
    // remote access is genuinely useful -- but it has to be opt-in, not the
    // default.
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (bindAddress.empty() || bindAddress == "0.0.0.0") {
        addr.sin_addr.s_addr = htonl(bindAddress.empty() ? INADDR_LOOPBACK
                                                         : INADDR_ANY);
    } else if (inet_pton(AF_INET, bindAddress.c_str(), &addr.sin_addr) != 1) {
        error_ = "invalid stats bind address '" + bindAddress + "'";
        closesocket(s);
        return false;
    }

    if (bind(s, reinterpret_cast<const sockaddr*>(&addr), sizeof addr) != 0) {
        error_ = "bind " + std::to_string(port) + ": " +
                 winsockErrorText(WSAGetLastError());
        closesocket(s);
        return false;
    }
    if (listen(s, 4) != 0) {
        error_ = "listen: " + winsockErrorText(WSAGetLastError());
        closesocket(s);
        return false;
    }

    // SO_RCVTIMEO does not apply to accept() on Windows, and closing a socket
    // that another thread is blocked in accept() on is not a dependable way to
    // wake it -- that hung the receiver on exit. Poll a non-blocking listener
    // instead, so the loop always notices running_ going false.
    u_long nonBlocking = 1;
    ioctlsocket(s, FIONBIO, &nonBlocking);

    sock_ = std::uintptr_t(s);
    running_ = true;
    error_.clear();
    thread_ = std::thread([this] { serve(); });
    return true;
}

void StatsServer::stop() {
    running_ = false;
    if (sock_ != kInvalid) {
        closesocket(SOCKET(sock_));
        sock_ = kInvalid;
    }
    if (thread_.joinable()) thread_.join();
}

void StatsServer::serve() {
    while (running_) {
        const SOCKET listener = SOCKET(sock_);
        if (listener == SOCKET(~std::uintptr_t(0))) break;

        fd_set rd;
        FD_ZERO(&rd);
        FD_SET(listener, &rd);
        timeval tv{0, 100 * 1000};          // 100 ms
        const int ready = select(0, &rd, nullptr, nullptr, &tv);
        if (ready <= 0) continue;           // timeout, or the socket went away

        SOCKET c = accept(listener, nullptr, nullptr);
        if (c == INVALID_SOCKET) continue;

        // The accepted socket inherits non-blocking mode; make it blocking so
        // the short request/response exchange below is straightforward.
        u_long blocking = 0;
        ioctlsocket(c, FIONBIO, &blocking);

        // Read and discard whatever the client sent; any request gets the same
        // answer.
        char scratch[1024];
        const DWORD to = 200;
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&to), sizeof to);
        recv(c, scratch, sizeof scratch, 0);

        std::string body = provider_ ? provider_() : std::string("no provider\n");
        std::string resp =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Cache-Control: no-store\r\n"
            "Connection: close\r\n"
            "Content-Length: " + std::to_string(body.size()) + "\r\n"
            "\r\n" + body;

        std::size_t off = 0;
        while (off < resp.size()) {
            const int n = ::send(c, resp.data() + off, int(resp.size() - off), 0);
            if (n <= 0) break;
            off += std::size_t(n);
        }
        shutdown(c, SD_BOTH);
        closesocket(c);
    }
}

}  // namespace pcapreplay
