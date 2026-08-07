#include "pcapreplay/nmos/http.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>

namespace pcapreplay::nmos {
namespace {

constexpr std::uintptr_t kInvalid = ~std::uintptr_t(0);
constexpr int kMaxBodyBytes = 4 * 1024 * 1024;

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return char(std::tolower(c)); });
    return s;
}

std::string trim(const std::string& s) {
    std::size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' ||
                     s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    return s.substr(a, b - a);
}

std::vector<std::string> split(const std::string& path) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : path) {
        if (c == '/') {
            if (!cur.empty()) { out.push_back(cur); cur.clear(); }
        } else {
            cur += c;
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

const char* reasonFor(int status) {
    switch (status) {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 400: return "Bad Request";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 409: return "Conflict";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        default:  return "Unknown";
    }
}

// Read until `terminator` appears or the peer closes. Returns false on error.
bool recvUntil(SOCKET s, const std::string& terminator, std::string& buf,
               std::size_t& at) {
    char chunk[8192];
    for (;;) {
        at = buf.find(terminator);
        if (at != std::string::npos) return true;
        if (buf.size() > 64 * 1024) return false;      // header flood
        const int n = recv(s, chunk, sizeof chunk, 0);
        if (n <= 0) return false;
        buf.append(chunk, std::size_t(n));
    }
}

bool sendAll(SOCKET s, const std::string& data) {
    std::size_t off = 0;
    while (off < data.size()) {
        const int n = ::send(s, data.data() + off, int(data.size() - off), 0);
        if (n <= 0) return false;
        off += std::size_t(n);
    }
    return true;
}

void setTimeouts(SOCKET s, int ms) {
    const DWORD to = DWORD(ms);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&to), sizeof to);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&to), sizeof to);
}

}  // namespace

std::string urlDecode(const std::string& s) {
    std::string o;
    o.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            auto hex = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            const int hi = hex(s[i + 1]), lo = hex(s[i + 2]);
            if (hi >= 0 && lo >= 0) { o += char(hi * 16 + lo); i += 2; continue; }
        }
        o += s[i] == '+' ? ' ' : s[i];
    }
    return o;
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

HttpServer::~HttpServer() { stop(); }

void HttpServer::route(const std::string& method, const std::string& pattern,
                       HttpHandler h) {
    Route r;
    r.method   = method;
    r.segments = split(pattern);
    if (!r.segments.empty() && r.segments.back() == "*") {
        r.wildcard = true;
        r.segments.pop_back();
    }
    r.handler = std::move(h);
    routes_.push_back(std::move(r));
}

std::uint16_t firstFreePort(const std::string& bindIp, std::uint16_t first, int span) {
    for (int i = 0; i < span; ++i) {
        const int candidate = int(first) + i;
        if (candidate > 65535) break;

        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return 0;
        const DWORD exclusive = 1;
        setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                   reinterpret_cast<const char*>(&exclusive), sizeof exclusive);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(std::uint16_t(candidate));
        if (bindIp.empty() || bindIp == "0.0.0.0") {
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
        } else if (inet_pton(AF_INET, bindIp.c_str(), &addr.sin_addr) != 1) {
            closesocket(s);
            return 0;                       // a bad address will not improve
        }

        const bool ok = bind(s, reinterpret_cast<const sockaddr*>(&addr),
                             sizeof addr) == 0;
        closesocket(s);
        if (ok) return std::uint16_t(candidate);
    }
    return 0;
}

bool HttpServer::start(const std::string& bindIp, std::uint16_t port) {
    stop();
    error_.clear();

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        error_ = "socket failed (" + std::to_string(WSAGetLastError()) + ")";
        return false;
    }
    // Exclusive, not SO_REUSEADDR -- see the note in stats_server.cpp. It
    // matters more here: this is a real network listener, so letting another
    // process bind the same port would let it answer NMOS requests on our
    // behalf. Binding a port already in use must fail loudly instead.
    const DWORD exclusive = 1;
    setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
               reinterpret_cast<const char*>(&exclusive), sizeof exclusive);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if (bindIp.empty() || bindIp == "0.0.0.0") {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (inet_pton(AF_INET, bindIp.c_str(), &addr.sin_addr) != 1) {
        error_ = "invalid bind address '" + bindIp + "'";
        closesocket(s);
        return false;
    }
    if (bind(s, reinterpret_cast<const sockaddr*>(&addr), sizeof addr) != 0) {
        error_ = "cannot bind " + (bindIp.empty() ? std::string("0.0.0.0") : bindIp) +
                 ":" + std::to_string(port) + " (" +
                 std::to_string(WSAGetLastError()) + ")";
        closesocket(s);
        return false;
    }
    if (listen(s, 16) != 0) {
        error_ = "listen failed (" + std::to_string(WSAGetLastError()) + ")";
        closesocket(s);
        return false;
    }

    // Report the port actually bound, which matters when 0 was requested: the
    // mDNS advertisement and the registry both have to carry the real one.
    sockaddr_in bound{};
    int blen = sizeof bound;
    if (getsockname(s, reinterpret_cast<sockaddr*>(&bound), &blen) == 0)
        port_ = ntohs(bound.sin_port);
    else
        port_ = port;

    // Non-blocking listener polled with select(), for the same reason as
    // StatsServer: closing a socket another thread is blocked in accept() on is
    // not a dependable way to wake it on Windows.
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);

    listener_ = std::uintptr_t(s);
    running_.store(true, std::memory_order_relaxed);

    for (int i = 0; i < 4; ++i) {
        workers_.emplace_back([this] {
            for (;;) {
                std::pair<std::uintptr_t, std::string> job;
                {
                    std::unique_lock<std::mutex> lk(queueMutex_);
                    queueCv_.wait(lk, [this] {
                        return !queue_.empty() ||
                               !running_.load(std::memory_order_relaxed);
                    });
                    if (queue_.empty()) return;
                    job = queue_.back();
                    queue_.pop_back();
                }
                serve(job.first, job.second);
            }
        });
    }
    acceptThread_ = std::thread([this] { accept(); });
    return true;
}

void HttpServer::stop() {
    running_.store(false, std::memory_order_relaxed);
    if (listener_ != kInvalid) {
        closesocket(SOCKET(listener_));
        listener_ = kInvalid;
    }
    queueCv_.notify_all();
    if (acceptThread_.joinable()) acceptThread_.join();
    for (auto& t : workers_)
        if (t.joinable()) t.join();
    workers_.clear();
    {
        std::lock_guard<std::mutex> lk(queueMutex_);
        for (auto& j : queue_) closesocket(SOCKET(j.first));
        queue_.clear();
    }
}

std::string HttpServer::lastRequestLine() const {
    std::lock_guard<std::mutex> lk(logMutex_);
    return lastLine_;
}

void HttpServer::accept() {
    while (running_.load(std::memory_order_relaxed)) {
        const SOCKET l = SOCKET(listener_);
        if (l == SOCKET(kInvalid)) break;

        fd_set rd;
        FD_ZERO(&rd);
        FD_SET(l, &rd);
        timeval tv{0, 100 * 1000};
        if (select(0, &rd, nullptr, nullptr, &tv) <= 0) continue;

        sockaddr_in from{};
        int flen = sizeof from;
        SOCKET c = ::accept(l, reinterpret_cast<sockaddr*>(&from), &flen);
        if (c == INVALID_SOCKET) continue;

        char ip[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &from.sin_addr, ip, sizeof ip);

        u_long blocking = 0;
        ioctlsocket(c, FIONBIO, &blocking);
        setTimeouts(c, 5000);

        {
            std::lock_guard<std::mutex> lk(queueMutex_);
            queue_.emplace_back(std::uintptr_t(c), std::string(ip));
        }
        queueCv_.notify_one();
    }
}

void HttpServer::serve(std::uintptr_t sockHandle, std::string peer) {
    const SOCKET s = SOCKET(sockHandle);
    std::string buf;
    std::size_t headerEnd = 0;
    if (!recvUntil(s, "\r\n\r\n", buf, headerEnd)) { closesocket(s); return; }

    const std::string head = buf.substr(0, headerEnd);
    std::string rest = buf.substr(headerEnd + 4);

    std::istringstream hs(head);
    std::string line;
    if (!std::getline(hs, line)) { closesocket(s); return; }

    HttpRequest req;
    req.peer = std::move(peer);
    {
        std::istringstream ls(line);
        std::string target, version;
        ls >> req.method >> target >> version;
        const std::size_t q = target.find('?');
        if (q == std::string::npos) {
            req.path = urlDecode(target);
        } else {
            req.path  = urlDecode(target.substr(0, q));
            req.query = target.substr(q + 1);
        }
    }
    while (std::getline(hs, line)) {
        const std::size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        req.headers[lower(trim(line.substr(0, colon)))] = trim(line.substr(colon + 1));
    }

    // Body. NMOS bodies are small and always Content-Length delimited, but a
    // proxy in the path can re-chunk them.
    const std::string te = lower(req.header("transfer-encoding"));
    if (te.find("chunked") != std::string::npos) {
        for (;;) {
            std::size_t at = 0;
            if (!recvUntil(s, "\r\n", rest, at)) break;
            const long long n = std::strtoll(rest.substr(0, at).c_str(), nullptr, 16);
            rest.erase(0, at + 2);
            if (n <= 0) break;
            while (rest.size() < std::size_t(n) + 2) {
                char chunk[8192];
                const int got = recv(s, chunk, sizeof chunk, 0);
                if (got <= 0) break;
                rest.append(chunk, std::size_t(got));
            }
            if (rest.size() < std::size_t(n)) break;
            req.body.append(rest, 0, std::size_t(n));
            rest.erase(0, std::size_t(n) + 2);
            if (req.body.size() > kMaxBodyBytes) break;
        }
    } else {
        const std::string cl = req.header("content-length");
        const std::size_t want =
            cl.empty() ? 0 : std::size_t(std::strtoull(cl.c_str(), nullptr, 10));
        if (want > kMaxBodyBytes) {
            closesocket(s);
            return;
        }
        req.body = rest;
        char chunk[8192];
        while (req.body.size() < want) {
            const int n = recv(s, chunk, sizeof chunk, 0);
            if (n <= 0) break;
            req.body.append(chunk, std::size_t(n));
        }
        req.body.resize(std::min(req.body.size(), want));
    }

    {
        std::lock_guard<std::mutex> lk(logMutex_);
        lastLine_ = req.method + " " + req.path + "  from " + req.peer;
    }
    served_.fetch_add(1, std::memory_order_relaxed);

    HttpResponse res;
    const bool handled = dispatch(req, res);
    if (!handled) {
        res.status = 404;
        res.contentType = "application/json";
        res.body = R"({"code":404,"error":"Not Found","debug":null})";
    }

    std::string out = "HTTP/1.1 " + std::to_string(res.status) + " " +
                      reasonFor(res.status) + "\r\n";
    out += "Content-Type: " + res.contentType + "\r\n";
    out += "Content-Length: " + std::to_string(res.body.size()) + "\r\n";
    // NMOS requires CORS on every response: the reference controllers are
    // browser applications and a node without these is simply invisible to them.
    out += "Access-Control-Allow-Origin: *\r\n";
    out += "Access-Control-Allow-Headers: Content-Type, Authorization\r\n";
    out += "Access-Control-Allow-Methods: GET, PUT, POST, HEAD, OPTIONS, DELETE, PATCH\r\n";
    out += "Access-Control-Expose-Headers: Content-Length, Location\r\n";
    out += "Access-Control-Max-Age: 3600\r\n";
    out += "Cache-Control: no-store\r\n";
    out += "Connection: close\r\n";
    for (const auto& h : res.extraHeaders)
        out += h.first + ": " + h.second + "\r\n";
    out += "\r\n";
    if (req.method != "HEAD") out += res.body;

    sendAll(s, out);
    shutdown(s, SD_BOTH);
    closesocket(s);
}

bool HttpServer::dispatch(HttpRequest& req, HttpResponse& res) {
    const std::vector<std::string> segs = split(req.path);

    // Preflight is answered generically: the CORS headers are on every response
    // already, so an OPTIONS only needs to succeed.
    bool pathExists = false;

    for (const Route& r : routes_) {
        if (r.wildcard) {
            if (segs.size() < r.segments.size()) continue;
        } else if (segs.size() != r.segments.size()) {
            continue;
        }
        std::map<std::string, std::string> params;
        bool match = true;
        for (std::size_t i = 0; i < r.segments.size(); ++i) {
            const std::string& pat = r.segments[i];
            if (!pat.empty() && pat[0] == ':') {
                params[pat.substr(1)] = segs[i];
            } else if (pat != segs[i]) {
                match = false;
                break;
            }
        }
        if (!match) continue;
        pathExists = true;

        const bool methodOk = r.method == req.method ||
                              (r.method == "GET" && req.method == "HEAD");
        if (!methodOk) continue;

        req.params = std::move(params);
        r.handler(req, res);
        return true;
    }

    if (req.method == "OPTIONS") {
        res.status = 204;
        res.contentType = "text/plain";
        res.body.clear();
        return true;
    }
    if (pathExists) {
        res.status = 405;
        res.body = R"({"code":405,"error":"Method Not Allowed","debug":null})";
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

HttpResult httpRequest(const std::string& host, std::uint16_t port,
                       const std::string& method, const std::string& target,
                       const std::string& body, const std::string& contentType,
                       int timeoutMs) {
    HttpResult r;

    addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* ai = nullptr;
    const std::string portText = std::to_string(port);
    if (getaddrinfo(host.c_str(), portText.c_str(), &hints, &ai) != 0 || !ai) {
        r.error = "cannot resolve " + host;
        return r;
    }

    SOCKET s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(ai);
        r.error = "socket failed";
        return r;
    }
    setTimeouts(s, timeoutMs);

    // Non-blocking connect so an unreachable registry times out in `timeoutMs`
    // rather than sitting in the stack's own 20-second retry.
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    const int rc = ::connect(s, ai->ai_addr, int(ai->ai_addrlen));
    if (rc != 0) {
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
            freeaddrinfo(ai);
            closesocket(s);
            r.error = "connect failed";
            return r;
        }
        fd_set wr, ex;
        FD_ZERO(&wr); FD_SET(s, &wr);
        FD_ZERO(&ex); FD_SET(s, &ex);
        timeval tv{timeoutMs / 1000, (timeoutMs % 1000) * 1000};
        if (select(0, nullptr, &wr, &ex, &tv) <= 0 || FD_ISSET(s, &ex)) {
            freeaddrinfo(ai);
            closesocket(s);
            r.error = "connect timed out";
            return r;
        }
    }
    freeaddrinfo(ai);
    nb = 0;
    ioctlsocket(s, FIONBIO, &nb);
    setTimeouts(s, timeoutMs);

    std::string req = method + " " + target + " HTTP/1.1\r\n";
    req += "Host: " + host + ":" + portText + "\r\n";
    req += "User-Agent: PCAP-Replay/1.0\r\n";
    req += "Accept: application/json\r\n";
    req += "Connection: close\r\n";
    if (!body.empty()) {
        req += "Content-Type: " + contentType + "\r\n";
        req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    }
    req += "\r\n";
    req += body;

    if (!sendAll(s, req)) {
        closesocket(s);
        r.error = "send failed";
        return r;
    }

    std::string buf;
    char chunk[8192];
    for (;;) {
        const int n = recv(s, chunk, sizeof chunk, 0);
        if (n <= 0) break;
        buf.append(chunk, std::size_t(n));
        if (buf.size() > kMaxBodyBytes) break;
    }
    closesocket(s);

    const std::size_t headEnd = buf.find("\r\n\r\n");
    if (headEnd == std::string::npos) {
        r.error = buf.empty() ? "no response" : "malformed response";
        return r;
    }

    std::istringstream hs(buf.substr(0, headEnd));
    std::string line;
    std::getline(hs, line);
    {
        const std::size_t sp = line.find(' ');
        if (sp != std::string::npos)
            r.status = std::atoi(line.substr(sp + 1).c_str());
    }
    while (std::getline(hs, line)) {
        const std::size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        r.headers[lower(trim(line.substr(0, colon)))] = trim(line.substr(colon + 1));
    }

    std::string payload = buf.substr(headEnd + 4);
    const auto te = r.headers.find("transfer-encoding");
    if (te != r.headers.end() && lower(te->second).find("chunked") != std::string::npos) {
        std::string decoded;
        std::size_t p = 0;
        while (p < payload.size()) {
            const std::size_t eol = payload.find("\r\n", p);
            if (eol == std::string::npos) break;
            const long long n = std::strtoll(payload.substr(p, eol - p).c_str(), nullptr, 16);
            p = eol + 2;
            if (n <= 0) break;
            decoded.append(payload, p, std::size_t(n));
            p += std::size_t(n) + 2;
        }
        payload = std::move(decoded);
    }
    r.body = std::move(payload);
    r.ok = true;
    return r;
}

}  // namespace pcapreplay::nmos
