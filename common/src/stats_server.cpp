#include "pcapreplay/stats_server.h"

#include "pcapreplay/platform.h"

namespace pcapreplay {
namespace {
constexpr std::uintptr_t kInvalid = kInvalidHandle;
}

StatsServer::~StatsServer() { stop(); }

bool StatsServer::start(std::uint16_t port, std::function<std::string()> provider,
                        const std::string& bindAddress) {
    stop();
    provider_ = std::move(provider);

    socket_t s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == kInvalidSocket) {
        error_ = "socket: " + socketErrorText(socketError());
        return false;
    }

    // Exclusive binding, not SO_REUSEADDR.
    //
    // On Windows SO_REUSEADDR lets a second process bind a port another process
    // is already listening on, and which of them then receives a connection is
    // not defined. That is a port hijack in general, and in practice it meant
    // this app silently answered with another replay tool's statistics.
    // SO_EXCLUSIVEADDRUSE is the fix there.
    //
    // POSIX needs no equivalent: a plain bind() already refuses a port that is
    // being listened on, so simply not asking for SO_REUSEADDR gives the same
    // property. Either way a second instance gets a clean failure it can step
    // past, rather than a shared port.
    setExclusiveBind(s);

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
        closeSocket(s);
        return false;
    }

    if (bind(s, reinterpret_cast<const sockaddr*>(&addr), sizeof addr) != 0) {
        error_ = "bind " + std::to_string(port) + ": " +
                 socketErrorText(socketError());
        closeSocket(s);
        return false;
    }
    if (listen(s, 4) != 0) {
        error_ = "listen: " + socketErrorText(socketError());
        closeSocket(s);
        return false;
    }

    // SO_RCVTIMEO does not apply to accept() on Windows, and closing a socket
    // that another thread is blocked in accept() on is not a dependable way to
    // wake it -- that hung the receiver on exit. Poll a non-blocking listener
    // instead, so the loop always notices running_ going false. The same shape
    // is kept on POSIX: closing a socket under a blocked accept() is undefined
    // there too, and a 100 ms poll costs nothing on a diagnostic endpoint.
    setNonBlocking(s, true);

    sock_ = toHandle(s);
    running_ = true;
    error_.clear();
    thread_ = std::thread([this] { serve(); });
    return true;
}

void StatsServer::stop() {
    running_ = false;
    if (thread_.joinable()) thread_.join();
    // Closed after the thread has gone, so the descriptor cannot be closed
    // while that thread is still selecting on it -- and, worse, reused by
    // another thread's socket() in between.
    if (sock_ != kInvalid) {
        closeSocket(fromHandle(sock_));
        sock_ = kInvalid;
    }
}

void StatsServer::serve() {
    while (running_) {
        const socket_t listener = fromHandle(sock_);
        if (listener == kInvalidSocket) break;

        fd_set rd;
        FD_ZERO(&rd);
        FD_SET(listener, &rd);
        timeval tv{0, 100 * 1000};          // 100 ms
        // nfds is ignored on Winsock and must be the highest descriptor plus
        // one on POSIX.
        const int ready = select(int(listener) + 1, &rd, nullptr, nullptr, &tv);
        if (ready <= 0) continue;           // timeout, or the socket went away

        socket_t c = accept(listener, nullptr, nullptr);
        if (c == kInvalidSocket) continue;

        // The accepted socket inherits non-blocking mode on Windows; make it
        // blocking so the short request/response exchange below is
        // straightforward. (POSIX does not inherit it, but setting it is
        // harmless and keeps the two the same.)
        setNonBlocking(c, false);

        // Read and discard whatever the client sent; any request gets the same
        // answer.
        char scratch[1024];
        const RecvTimeout to(200);
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, to.data(), to.size());
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
            const auto n = ::send(c, resp.data() + off, int(resp.size() - off), 0);
            if (n <= 0) break;
            off += std::size_t(n);
        }
        shutdown(c, SHUT_RDWR);
        closeSocket(c);
    }
}

}  // namespace pcapreplay
