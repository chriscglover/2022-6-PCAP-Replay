// A tiny localhost stats endpoint.
//
// The app exposes its live counters over HTTP on 127.0.0.1 so they can be read
// by anything -- a browser, curl, a script -- without transcribing numbers out
// of a dialog box. Bound to loopback only; this is a diagnostic surface, not a
// network service.
//
//   replay   http://127.0.0.1:49610/
//
// 49610 is chosen because it is not normally in use, so the status endpoint is
// unlikely to collide with anything else on the machine.
//
// Note this is NOT the NMOS HTTP server: that one has to be reachable from the
// registry and from controllers, so it binds a real interface and lives in
// nmos/http_server.h. Keeping the two separate keeps the diagnostic surface
// local even when the NMOS node is exposed.
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <thread>

namespace pcapreplay {

inline constexpr std::uint16_t kReplayStatsPort = 49610;   // http://127.0.0.1:49610/

class StatsServer {
public:
    StatsServer() = default;
    ~StatsServer();
    StatsServer(const StatsServer&) = delete;
    StatsServer& operator=(const StatsServer&) = delete;

    // `provider` is called on the server thread for each request. It must be
    // safe to call concurrently with the rest of the application.
    //
    // `bindAddress` defaults to loopback. Binding all interfaces ("0.0.0.0")
    // makes an unsigned, freshly-built executable into a network listener,
    // which Windows Defender's ML classifier flags as malware -- it quarantined
    // this very binary. It is also simply better practice for a diagnostic
    // surface to be local unless someone asks otherwise.
    bool start(std::uint16_t port,
               std::function<std::string()> provider,
               const std::string& bindAddress = "127.0.0.1");

    // Step to the next free port when the requested one is already listening,
    // exactly as the NMOS node does with 3210. A second copy on one machine
    // should still get a stats page rather than losing its only scriptable
    // surface to the first one, and nothing depends on the number: it is
    // printed, shown in the dialog and reported by port().
    //
    // Only a port collision steps. A bad bind address will not improve at the
    // next port, so that fails once and says what was wrong.
    bool startNear(std::uint16_t first, int span,
                   std::function<std::string()> provider,
                   const std::string& bindAddress = "127.0.0.1");

    void stop();

    bool running() const { return running_; }
    // What was actually bound, which is not necessarily what was asked for --
    // see startNear. Zero when nothing is listening.
    std::uint16_t port() const { return port_; }
    const std::string& error() const { return error_; }

private:
    void serve();

    std::uintptr_t sock_ = ~0ull;
    std::thread    thread_;
    std::function<std::string()> provider_;
    volatile bool  running_ = false;
    std::uint16_t  port_ = 0;
    // Whether the last failed start() failed at bind(), which is the only
    // failure another port could cure.
    bool           bindFailed_ = false;
    std::string    error_;
};

}  // namespace pcapreplay
