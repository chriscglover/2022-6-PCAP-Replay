// Console driver for the same engines the GUI uses.
//
// On Windows this exists alongside the dialog, so the streaming ingest, the
// ST 2022-7 merge and the NMOS node can be exercised and measured without a
// dialog box in the way, and so a replay can be scripted.
//
// On Linux it is the whole product. There is no dialog and there is not meant to
// be one: the machines this runs on are servers and containers, and everything
// the dialog offered is here as a flag -- the per-path NIC and multicast group,
// the fault injection, the NMOS configuration, and the same status panel served
// over HTTP. See --help.
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <thread>

#include "pcapreplay/hbrmt.h"
#include "pcapreplay/net_interfaces.h"
#include "pcapreplay/net_multicast.h"
#include "pcapreplay/pcap_reader.h"
#include "pcapreplay/pcap_source.h"
#include "pcapreplay/replay_engine.h"
#include "pcapreplay/stats_server.h"
#include "pcapreplay/status_text.h"
#include "pcapreplay/nmos/http.h"
#include "pcapreplay/nmos/mdns.h"
#include "pcapreplay/nmos/nmos_node.h"
#include "pcapreplay/nmos/status_text.h"
// Version only. Shared with the GUI and VERSIONINFO so there is one constant to
// bump, not three that can disagree about what build this is.
#include "resource.h"

using namespace pcapreplay;

namespace {

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

// Set from a signal handler, so nothing but a flag and a write to a
// self-pipe-free atomic happens in it.
//
// This matters more than it looks. A replay that is killed without unwinding
// leaves its registration in the registry and its advertisement on the link, and
// a controller then lists a sender that is not there -- which is exactly the
// failure this tool exists to help diagnose. Ctrl-C and `systemctl stop` (which
// sends SIGTERM) both have to take the node down properly.
std::atomic<bool> g_stop{false};
std::atomic<int>  g_signal{0};

extern "C" void onSignal(int sig) {
    g_signal.store(sig, std::memory_order_relaxed);
    g_stop.store(true, std::memory_order_relaxed);
}

void installSignalHandlers() {
#ifdef _WIN32
    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);
#else
    struct sigaction sa {};
    sa.sa_handler = onSignal;
    sigemptyset(&sa.sa_mask);
    // No SA_RESTART: a blocking recv in a worker should come back as EINTR
    // rather than sit there while the process is trying to leave.
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    // SIGHUP arrives when the terminal that started this goes away. Treat it as
    // a stop rather than letting the default action kill the process outright,
    // so the registry is told.
    sigaction(SIGHUP, &sa, nullptr);
#endif
}

const char* signalName(int sig) {
    switch (sig) {
        case SIGINT:  return "SIGINT";
        case SIGTERM: return "SIGTERM";
#ifndef _WIN32
        case SIGHUP:  return "SIGHUP";
#endif
        default:      return "signal";
    }
}

// ---------------------------------------------------------------------------

void printProbe(const PcapProbe& p) {
    if (!p.ok) {
        std::printf("probe failed: %s\n", p.error.c_str());
        return;
    }
    std::printf("format        : %s\n", p.formatText.c_str());
    std::printf("red           : %s  (%.2f GB)\n", p.redAddress.c_str(),
                double(p.redBytes) / (1ull << 30));
    if (!p.blueAddress.empty())
        std::printf("blue          : %s  (%.2f GB)\n", p.blueAddress.c_str(),
                    double(p.blueBytes) / (1ull << 30));
    std::printf("estimated     : %.1f s of capture\n", p.estimatedSeconds);
    if (!p.warning.empty()) std::printf("warning       : %s\n", p.warning.c_str());
}

// What every interface on this machine is called and where it goes.
//
// The single most common way to get nothing on the wire is to send out of the
// wrong NIC, and on Linux the answer is not obvious: a workstation with Docker
// on it has docker0 and a bridge per compose network, all up and all
// multicast-capable. This prints the same ordering the GUI's dropdown uses --
// physical before virtual, fastest first -- so the top entry is nearly always
// the right one.
int listInterfaces() {
    const auto ifaces = enumerateInterfaces(true);
    std::printf("%-12s %-16s %-10s %-19s %s\n",
                "NAME", "ADDRESS", "SPEED", "MAC", "NOTES");
    for (const auto& ni : ifaces) {
        std::string speed = "-";
        if (ni.speedBps >= 1000000000ull)
            speed = std::to_string(ni.speedBps / 1000000000ull) + " Gb/s";
        else if (ni.speedBps >= 1000000ull)
            speed = std::to_string(ni.speedBps / 1000000ull) + " Mb/s";

        std::string notes;
        if (!ni.up)              notes += "down ";
        if (ni.loopback)         notes += "loopback ";
        if (ni.virtualAdapter)   notes += "virtual ";
        if (!ni.multicastCapable) notes += "no-multicast ";
        if (notes.empty())       notes = "usable";

        std::printf("%-12s %-16s %-10s %-19s %s\n",
                    ni.name.c_str(), ni.ipv4.c_str(), speed.c_str(),
                    ni.mac.empty() ? "-" : ni.mac.c_str(), notes.c_str());
    }
    std::printf("\nPass either the name or the address to --iface.\n");
    return 0;
}

// --iface takes a name or an address. On Linux the name is what everything else
// on the machine calls the interface, and making someone read an address out of
// `ip addr` first is needless friction; on Windows the address is the thing the
// multicast API actually wants. Both work on both.
std::string resolveIface(const std::string& given, std::string& error) {
    if (given.empty()) return {};
    NetInterface ni;
    if (findInterfaceByIp(given, ni)) return ni.ipv4;
    if (findInterfaceByName(given, ni)) {
        if (ni.ipv4.empty()) {
            error = "interface '" + given + "' has no IPv4 address";
            return {};
        }
        return ni.ipv4;
    }
    error = "no interface called '" + given + "' -- run --interfaces to see them";
    return {};
}

// Browse for registries and print what turns up. Answers the question on its own
// terms: whether this machine, on this segment, can see an NMOS registry over
// mDNS at all -- separately from whether the node then manages to register.
int discover(double seconds, const std::string& apiVersion) {
    nmos::MdnsBrowser browser;
    const std::vector<std::string> types = nmos::registryServiceTypes();

    std::printf("browsing for %.0f s:", seconds);
    for (const auto& t : types) std::printf("  %s", t.c_str());
    std::printf("\n");
    // Both types matter. A registry serving IS-04 v1.2 and below advertises only
    // _nmos-registration._tcp; the shorter _nmos-register._tcp arrived at v1.3.
    if (!browser.start(types)) {
        std::printf("\nbrowse failed: %s\n", browser.error().c_str());
        std::printf("The segment has to carry multicast DNS, and this machine has\n"
                    "to be able to send to 224.0.0.251. Use --registry HOST:PORT\n"
                    "if it does not.\n");
        return 1;
    }
    // Non-fatal trouble, e.g. UDP 5353 already held by avahi-daemon in a way
    // that could not be shared. Browsing still works from a private port, but
    // it is worth knowing about.
    if (!browser.error().empty())
        std::printf("note: %s\n", browser.error().c_str());

    const auto deadline =
        std::chrono::steady_clock::now() +
        std::chrono::milliseconds(std::int64_t(seconds * 1000.0));
    std::size_t reported = 0;
    while (std::chrono::steady_clock::now() < deadline &&
           !g_stop.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        const auto found = browser.found();
        for (std::size_t i = reported; i < found.size(); ++i) {
            const nmos::MdnsService& m = found[i];
            std::printf("\n  %s\n", m.displayName.c_str());
            std::printf("    type      : %s\n", m.serviceType.c_str());
            std::printf("    host      : %s\n", m.hostName.c_str());
            std::printf("    address   : %s:%u\n",
                        m.address.empty() ? "(unresolved)" : m.address.c_str(),
                        unsigned(m.port));
            std::printf("    priority  : %d\n", m.priority);
            std::printf("    api_ver   : ");
            if (m.apiVersions.empty()) std::printf("(not advertised)");
            for (std::size_t k = 0; k < m.apiVersions.size(); ++k)
                std::printf("%s%s", k ? "," : "", m.apiVersions[k].c_str());
            std::printf("\n    api_proto : %s\n", m.apiProto.c_str());
            if (m.port)
                std::printf("    would use : %s\n", m.baseUrl(apiVersion).c_str());
        }
        reported = found.size();
    }

    std::printf("\n%zu registry advertisement(s) seen\n", reported);

    nmos::MdnsService best;
    if (browser.best(apiVersion, best)) {
        std::printf("would register with: %s\n", best.baseUrl(apiVersion).c_str());
        browser.stop();
        return 0;
    }

    const std::string why = browser.rejection(apiVersion);
    if (!why.empty()) std::printf("no usable registry: %s\n", why.c_str());
    else std::printf("no registry found. Either none is advertising on this "
                     "segment, or mDNS is not carried between subnets here --\n"
                     "use --registry HOST:PORT in that case.\n");
    browser.stop();
    return 1;
}

void usage() {
    std::printf(
APP_NAME " " APP_VERSION_STR " - ST 2022-6/-7 replay from packet capture, with NMOS\n"
"\n"
"usage: replay_cli <red.pcap> [blue.pcap] [options]\n"
"       replay_cli --discover [seconds]      (no capture needed)\n"
"       replay_cli --interfaces              (no capture needed)\n"
"\n"
"Give one capture for a plain ST 2022-6 replay, or both legs of an ST 2022-7\n"
"pair to have them merged -- a datagram missing from one leg is filled from the\n"
"other. Captures are streamed off disk, so a multi-gigabyte file plays in full\n"
"and loops seamlessly: RTP sequence, timestamp, SSRC and the HBRMT frame count\n"
"are all generated fresh, so the loop join is invisible to a receiver.\n"
"\n"
"inspect\n"
"  --probe                identify the capture(s) and exit\n"
"  --gaps                 walk one capture and report where its RTP sequence\n"
"                         actually jumps, independently of the merge -- settles\n"
"                         whether a hole count comes from the file or the reader\n"
"  --ingest N             run the source alone for N seconds and measure how\n"
"                         fast frames come off this disk. That is what decides\n"
"                         whether a capture can be replayed at line rate at all\n"
"  --sdp                  print the SDP a controller would fetch, and exit\n"
"  --interfaces           list this machine's NICs and exit\n"
"  --discover [N]         browse for NMOS registries over mDNS for N seconds\n"
"                         (default 5). Settles \"is a registry visible from\n"
"                         here\" before anything else is blamed\n"
"\n"
"transmit\n"
"  --group A              path A destination        (default 239.1.1.1)\n"
"  --group-b B            path B destination; giving it enables ST 2022-7\n"
"  --port N               destination port          (default 40000)\n"
"  --iface IF             outgoing interface, by name or address, for both\n"
"                         paths. Strongly recommended: without it multicast\n"
"                         leaves by the default route, which on a box with\n"
"                         Docker on it is very often the wrong link\n"
"  --iface-b IF           a different interface for path B, for real -7\n"
"                         redundancy across two NICs\n"
"  --ttl N                multicast TTL             (default 8)\n"
"  --no-loopback          do not deliver to receivers on this machine\n"
"  --seconds N            stop after N seconds      (default: run until killed)\n"
"  --ring N               ring buffer depth, frames (default 16)\n"
"  --skip N               consecutive bad frames before looping (default 10)\n"
"  --no-timecode          leave the captured ATC timecode alone rather than\n"
"                         rewriting it to this machine's time of day\n"
"\n"
"faults -- random, not periodic, so they cannot line up with a receiver's own\n"
"buffering and either flatter or unfairly punish it\n"
"  --fault-loss-a         drop individual datagrams on path A\n"
"  --fault-loss-b         ... and on path B, independently. With both legs on\n"
"                         and losses independent, a working -7 receiver shows\n"
"                         no errors at all -- which is the test\n"
"  --fault-burst          drop a short run, as a real glitch does\n"
"  --fault-reorder        swap adjacent datagrams\n"
"  --fault-duplicate      send a datagram twice\n"
"  --fault-seqjump        sequence discontinuity, as after a restart\n"
"  --fault-rate P         probability per datagram per enabled fault, percent\n"
"                         (default 0.10)\n"
"\n"
"NMOS\n"
"  --nmos                 register as an IS-04 sender and serve IS-05, so a\n"
"                         controller can route this like any other kit\n"
"  --nmos-port N          node API port             (default 3210)\n"
"  --label TEXT           sender label in the controller (default \"PCAP Replay\")\n"
"  --registry H:P         registry override, skips mDNS discovery\n"
"  --no-p2p               do not advertise _nmos-node._tcp for peer-to-peer\n"
"  --idle                 register, but do not transmit until a controller\n"
"                         activates the sender over IS-05. Without it the\n"
"                         replay starts immediately, as pressing Start does\n"
"\n"
"status\n"
"  --stats-port N         serve the status panel over HTTP (default 49610).\n"
"                         Taken ports step up, so a second instance lands on\n"
"                         49611; the line printed at start says which\n"
"  --stats-bind ADDR      address to serve it on (default 127.0.0.1; use\n"
"                         0.0.0.0 to reach it from another machine)\n"
"  --no-stats             do not serve it at all\n"
"  --interval N           seconds between console reports (default 2, 0 = off)\n"
"  --quiet                no periodic console report\n"
"  -h, --help             this\n");
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        usage();
        return 2;
    }

    std::string red, blue;
    std::string groupA = "239.1.1.1", groupB, ifaceArg, ifaceBArg, label;
    int  port = 40000, ring = 16, skip = 10, nmosPort = 3210, ttl = 8;
    double seconds = 0.0, ingestSeconds = 0.0, reportInterval = 2.0;
    bool probeOnly = false, timecode = true, wantNmos = false, wantSdp = false;
    bool wantGaps = false, wantDiscover = false, wantInterfaces = false;
    bool loopback = true, peerToPeer = true, idle = false;
    bool wantStats = true, quiet = false;
    int  statsPort = int(kReplayStatsPort);
    std::string statsBind = "127.0.0.1";
    double discoverSeconds = 5.0;
    std::string registry;
    ReplayFaults faults;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto val = [&]() -> std::string { return i + 1 < argc ? argv[++i] : ""; };
        if      (a == "-h" || a == "--help") { usage(); return 0; }
        else if (a == "--probe")       probeOnly = true;
        else if (a == "--interfaces")  wantInterfaces = true;
        else if (a == "--discover") {
            wantDiscover = true;
            // The duration is optional, so only swallow the next argument when
            // it is actually a number rather than the next flag or a filename.
            if (i + 1 < argc && argv[i + 1][0] >= '0' && argv[i + 1][0] <= '9')
                discoverSeconds = std::atof(argv[++i]);
            if (discoverSeconds <= 0.0) discoverSeconds = 5.0;
        }
        else if (a == "--gaps")        wantGaps = true;
        else if (a == "--ingest")      ingestSeconds = std::atof(val().c_str());
        else if (a == "--sdp")         wantSdp = true;
        else if (a == "--group")       groupA = val();
        else if (a == "--group-b")     groupB = val();
        else if (a == "--port")        port = std::atoi(val().c_str());
        else if (a == "--iface")       ifaceArg = val();
        else if (a == "--iface-b")     ifaceBArg = val();
        else if (a == "--ttl")         ttl = std::atoi(val().c_str());
        else if (a == "--no-loopback") loopback = false;
        else if (a == "--seconds")     seconds = std::atof(val().c_str());
        else if (a == "--ring")        ring = std::atoi(val().c_str());
        else if (a == "--skip")        skip = std::atoi(val().c_str());
        else if (a == "--no-timecode") timecode = false;
        else if (a == "--fault-loss-a")    faults.lossA = true;
        else if (a == "--fault-loss-b")    faults.lossB = true;
        else if (a == "--fault-burst")     faults.burstLoss = true;
        else if (a == "--fault-reorder")   faults.reorder = true;
        else if (a == "--fault-duplicate") faults.duplicate = true;
        else if (a == "--fault-seqjump")   faults.seqJump = true;
        else if (a == "--fault-rate")      faults.ratePercent = std::atof(val().c_str());
        else if (a == "--nmos")        wantNmos = true;
        else if (a == "--nmos-port")   nmosPort = std::atoi(val().c_str());
        else if (a == "--label")       label = val();
        else if (a == "--registry")    registry = val();
        else if (a == "--no-p2p")      peerToPeer = false;
        else if (a == "--idle")        idle = true;
        else if (a == "--stats-port")  statsPort = std::atoi(val().c_str());
        else if (a == "--stats-bind")  statsBind = val();
        else if (a == "--no-stats")    wantStats = false;
        else if (a == "--interval")    reportInterval = std::atof(val().c_str());
        else if (a == "--quiet")       quiet = true;
        else if (!a.empty() && a[0] != '-') {
            if (red.empty()) red = a; else blue = a;
        } else {
            std::printf("unknown option %s   (--help for the list)\n", a.c_str());
            return 2;
        }
    }
    if (quiet) reportInterval = 0.0;

    WinsockScope ws;
    installSignalHandlers();

    // Both of these answer a question about the machine rather than about a
    // capture, so demanding a pcap to run them would be daft.
    if (wantInterfaces) return listInterfaces();
    if (wantDiscover)   return discover(discoverSeconds, "v1.3");

    std::string ifaceError;
    const std::string iface = resolveIface(ifaceArg, ifaceError);
    if (!ifaceError.empty()) { std::printf("%s\n", ifaceError.c_str()); return 2; }
    const std::string ifaceB =
        ifaceBArg.empty() ? iface : resolveIface(ifaceBArg, ifaceError);
    if (!ifaceError.empty()) { std::printf("%s\n", ifaceError.c_str()); return 2; }

    if (red.empty()) {
        std::printf("no capture given.   (--help for the list)\n");
        return 2;
    }

    const PcapProbe p = PcapSource::probe(red, blue);
    printProbe(p);
    if (!p.ok) return 1;
    if (probeOnly) return 0;

    // ---- independent sequence-gap audit ------------------------------------
    if (wantGaps) {
        PcapReader rd;
        if (!rd.open(red)) { std::printf("%s\n", rd.error.c_str()); return 1; }
        std::vector<std::uint8_t> pkt;
        std::uint32_t dst = 0;
        std::uint64_t n = 0, gaps = 0, missing = 0, markers = 0;
        std::uint64_t firstSeq = 0, lastAbs = 0, firstMarkerAt = 0;
        bool started = false;
        int shown = 0;

        while (rd.next(pkt) && !g_stop.load(std::memory_order_relaxed)) {
            UdpView u;
            if (!parseUdp(pkt.data(), pkt.size(), u, rd.linktype)) continue;
            ParsedDatagram pd{};
            if (!parseDatagram({u.payload, u.len}, pd)) continue;
            if (pd.payload.size() != kHbrmtPayloadBytes) continue;
            if (!dst) dst = u.dstIp;
            if (u.dstIp != dst) continue;

            const std::uint16_t raw = pd.rtp.sequence;
            if (!started) {
                started = true;
                firstSeq = raw;
                lastAbs = raw;
            } else {
                const std::uint64_t abs = std::uint64_t(
                    std::int64_t(lastAbs) + std::int16_t(raw - std::uint16_t(lastAbs)));
                if (abs != lastAbs + 1) {
                    ++gaps;
                    const std::int64_t d = std::int64_t(abs) - std::int64_t(lastAbs) - 1;
                    missing += std::uint64_t(d > 0 ? d : 0);
                    if (shown < 8) {
                        std::printf("  gap %llu: after packet %llu, seq %llu -> %llu "
                                    "(%lld missing)\n",
                                    (unsigned long long)gaps, (unsigned long long)n,
                                    (unsigned long long)lastAbs, (unsigned long long)abs,
                                    (long long)d);
                        ++shown;
                    }
                }
                lastAbs = abs;
            }
            if (pd.rtp.marker) {
                if (!markers) firstMarkerAt = n;
                ++markers;
            }
            ++n;
        }
        rd.close();
        std::printf("\n%llu datagrams, first seq %llu, last seq %llu\n",
                    (unsigned long long)n, (unsigned long long)firstSeq,
                    (unsigned long long)lastAbs);
        std::printf("span %llu, so %llu sequence numbers are absent\n",
                    (unsigned long long)(lastAbs - firstSeq + 1),
                    (unsigned long long)(lastAbs - firstSeq + 1 - n));
        std::printf("%llu discontinuities, %llu missing datagrams\n",
                    (unsigned long long)gaps, (unsigned long long)missing);
        std::printf("%llu markers; first marker at packet %llu\n",
                    (unsigned long long)markers, (unsigned long long)firstMarkerAt);
        return 0;
    }

    // ---- ingest-only: how fast can frames come off the disk? --------------
    if (ingestSeconds > 0.0) {
        PcapSourceConfig sc;
        sc.fileRed = red;
        sc.fileBlue = blue;
        sc.ringFrames = ring;
        sc.skipTolerance = skip;

        PcapSource src;
        if (!src.start(sc)) {
            std::printf("source failed: %s\n", src.status().error.c_str());
            return 1;
        }
        const double target = ::pcapreplay::formatInfo(p.format).frameRate();
        std::printf("\ningesting for %.0f s, target %.2f fps to keep up with line rate\n",
                    ingestSeconds, target);

        const auto t0 = std::chrono::steady_clock::now();
        std::uint64_t frames = 0;
        bool repeated = false;
        double lastReport = 0.0;
        std::uint64_t lastFrames = 0;
        for (;;) {
            if (g_stop.load(std::memory_order_relaxed)) break;
            const std::uint8_t* f = src.next(2000, repeated);
            if (!f) break;
            if (!repeated) ++frames;
            const double el =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            if (el >= ingestSeconds) break;
            if (el - lastReport >= 2.0) {
                const PcapSourceStatus s = src.status();
                std::printf("  %5.1fs  %6.2f fps  ring %2d/%-2d  read %6.0f Mb/s  "
                            "pos %5.1f%%  loops %llu/%llu  holes %s  filled %s\n",
                            el, double(frames - lastFrames) / (el - lastReport),
                            s.ringFill, s.ringDepth, s.readMbps, s.progress * 100.0,
                            (unsigned long long)s.loops, (unsigned long long)s.earlyLoops,
                            commas(s.sequenceHoles).c_str(),
                            commas(s.filledFromBlue).c_str());
                lastReport = el;
                lastFrames = frames;
            }
        }
        const double el =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        const PcapSourceStatus s = src.status();
        src.releaseAll();
        src.stop();

        std::printf("\n%llu frames in %.1f s = %.2f fps  (need %.2f, %s)\n",
                    (unsigned long long)frames, el, double(frames) / el, target,
                    double(frames) / el >= target ? "keeps up" : "TOO SLOW");
        std::printf("rejected raster %s, short %s, hole %s; sequence holes %s; "
                    "filled from blue %s\n",
                    commas(s.framesRejectedRaster).c_str(),
                    commas(s.framesRejectedShort).c_str(),
                    commas(s.framesRejectedHole).c_str(),
                    commas(s.sequenceHoles).c_str(),
                    commas(s.filledFromBlue).c_str());
        if (!s.warning.empty()) std::printf("warning: %s\n", s.warning.c_str());
        if (!s.error.empty())   std::printf("error  : %s\n", s.error.c_str());
        return 0;
    }

    // ---- replay ------------------------------------------------------------
    ReplayConfig cfg;
    cfg.fileRed  = red;
    cfg.fileBlue = blue;
    cfg.ringFrames = ring;
    cfg.skipTolerance = skip;
    cfg.enablePathB = !groupB.empty();
    cfg.pathA.group = groupA;
    cfg.pathA.port  = std::uint16_t(port);
    cfg.pathA.interfaceIp = iface;
    cfg.pathB.group = groupB;
    cfg.pathB.port  = std::uint16_t(port);
    cfg.pathB.interfaceIp = ifaceB;
    cfg.ttl = ttl;
    cfg.loopback = loopback;
    cfg.rewriteTimecode = timecode;
    cfg.maxSeconds = seconds;
    cfg.faults = faults;

    // Say no to a configuration that cannot work, here, rather than letting it
    // fail as an empty link somebody then goes looking for with a capture.
    if (!isValidMulticastGroup(cfg.pathA.group)) {
        std::printf("\n%s is not a usable multicast group (224.0.0.0/4, and not "
                    "the 224.0.0.0/24 control block)\n", cfg.pathA.group.c_str());
        return 2;
    }
    if (cfg.enablePathB) {
        if (!isValidMulticastGroup(cfg.pathB.group)) {
            std::printf("\n%s is not a usable multicast group\n", cfg.pathB.group.c_str());
            return 2;
        }
        if (cfg.pathA.group == cfg.pathB.group && cfg.pathA.port == cfg.pathB.port) {
            std::printf("\nboth ST 2022-7 legs would point at %s:%d, which is not "
                        "redundancy\n", cfg.pathA.group.c_str(), cfg.pathA.port);
            return 2;
        }
    }

    // The engine and the NMOS node reach for this pair together: an IS-05
    // activation arrives on an HTTP worker thread while the main loop is
    // reading status.
    std::mutex controlMutex;
    std::unique_ptr<nmos::NmosBackend> node(nmos::createBuiltinBackend());
    ReplayEngine engine;

    auto query = [&]() {
        std::lock_guard<std::mutex> lk(controlMutex);
        nmos::SenderTransport t;
        // While the engine is running, report what it is actually transmitting,
        // not what was asked for. The two do come apart -- an IS-05 activation
        // that failed to restart the engine would otherwise have the Node API,
        // the IS-05 active endpoint and the SDP all confidently advertising a
        // group nothing is being sent to. A controller believes the manifest, so
        // a wrong one is worse than a stale one.
        const bool live = engine.running();
        const ReplayConfig liveCfg = engine.activeConfig();
        const ReplayConfig& c = live ? liveCfg : cfg;

        t.active     = live;
        t.redundant  = c.enablePathB;
        t.sourceIpA  = c.pathA.interfaceIp;
        t.sourceIpB  = c.pathB.interfaceIp;
        t.destIpA    = c.pathA.group;
        t.destPortA  = c.pathA.port;
        t.destIpB    = c.pathB.group;
        t.destPortB  = c.pathB.port;
        t.ttl        = c.ttl;
        t.ssrc       = c.ssrc;
        t.interfaceNameA = c.pathA.interfaceIp;
        t.interfaceNameB = c.pathB.interfaceIp;
        for (const auto& ni : enumerateInterfaces()) {
            if (ni.ipv4 == c.pathA.interfaceIp) {
                t.macA = ni.mac;
                t.interfaceNameA = ni.name;
            }
            if (ni.ipv4 == c.pathB.interfaceIp) {
                t.macB = ni.mac;
                t.interfaceNameB = ni.name;
            }
        }
        if (t.interfaceNameA.empty()) t.interfaceNameA = "any";
        if (t.interfaceNameB.empty()) t.interfaceNameB = "any";

        const SdiFormatInfo& fi = ::pcapreplay::formatInfo(p.format);
        t.frameRateNum = fi.frameRateNum;
        t.frameRateDen = fi.frameRateDen;
        t.formatText   = p.formatText;
        return t;
    };

    if (wantSdp) {
        // Bring the node up on an ephemeral port purely to render the SDP the
        // way a controller would fetch it, then take it down again.
        nmos::NmosConfig n;
        n.enabled = true;
        n.nodePort = 0;
        n.useMdns = false;
        n.advertisePeerToPeer = false;
        if (!label.empty()) n.label = label;
        node->setCallbacks(query, [](const nmos::SenderTransport&, std::string&) {
            return true;
        });
        if (!node->start(n)) {
            std::printf("nmos failed: %s\n", node->status().error.c_str());
            return 1;
        }
        const nmos::NmosStatus st = node->status();
        std::string hostPort = st.nodeApiUrl;
        const std::size_t a = hostPort.find("://") + 3;
        const std::size_t b = hostPort.find('/', a);
        hostPort = hostPort.substr(a, b - a);
        const std::size_t colon = hostPort.rfind(':');
        const auto r = nmos::httpRequest(
            hostPort.substr(0, colon),
            std::uint16_t(std::atoi(hostPort.c_str() + colon + 1)),
            "GET", "/x-nmos/connection/v1.1/single/senders/" + st.senderId +
                   "/transportfile");
        std::printf("\n--- SDP (%d) ---\n%s\n", r.status, r.body.c_str());
        node->stop();
        return 0;
    }

    // ---- the status endpoint ----------------------------------------------
    //
    // Started before anything else so it can report a failure to start the rest.
    StatsServer stats;
    std::atomic<bool> nmosEnabled{wantNmos};
    if (wantStats) {
        // Step to the next free port rather than losing the status endpoint to
        // whatever already holds this one -- the same courtesy the NMOS node
        // does for 3210, and what makes a second instance on one machine
        // usable. The port actually bound is printed below.
        const bool ok = stats.startNear(std::uint16_t(statsPort), 20, [&] {
            std::string out = APP_NAME " " APP_VERSION_STR "\n\n";
            out += statusText(engine.status(), "\n");
            out += "\n-- nmos --------------------------------------------\n";
            out += nmos::statusText(node->status(),
                                    nmosEnabled.load(std::memory_order_relaxed), "\n");
            return out;
        }, statsBind);
        if (!ok)
            std::printf("status endpoint unavailable: %s\n", stats.error().c_str());
        else if (!quiet)
            std::printf("status: http://%s:%d/\n", statsBind.c_str(),
                        int(stats.port()));
    }

    if (wantNmos) {
        nmos::NmosConfig n;
        n.enabled  = true;
        n.nodeIp   = iface;
        n.nodePort = std::uint16_t(nmosPort);
        n.advertisePeerToPeer = peerToPeer;
        if (!label.empty()) n.label = label;
        if (!registry.empty()) {
            const std::size_t colon = registry.rfind(':');
            n.useMdns = false;
            n.registryHost = registry.substr(0, colon);
            n.registryPort = std::uint16_t(colon == std::string::npos
                                               ? 3210
                                               : std::atoi(registry.c_str() + colon + 1));
        }
        node->setCallbacks(query, [&](const nmos::SenderTransport& want,
                                      std::string& err) {
            {
                std::lock_guard<std::mutex> lk(controlMutex);
                cfg.pathA.group = want.destIpA;
                cfg.pathA.port  = want.destPortA;
                if (cfg.enablePathB) {
                    cfg.pathB.group = want.destIpB;
                    cfg.pathB.port  = want.destPortB;
                }
                if (want.active) {
                    if (!isValidMulticastGroup(cfg.pathA.group)) {
                        err = "destination_ip " + cfg.pathA.group +
                              " is not a usable multicast group";
                        return false;
                    }
                    if (cfg.enablePathB && !isValidMulticastGroup(cfg.pathB.group)) {
                        err = "second leg destination_ip " + cfg.pathB.group +
                              " is not a usable multicast group";
                        return false;
                    }
                    engine.start(cfg);
                } else {
                    engine.stop();
                    std::printf("[nmos] IS-05: sender disabled\n");
                    std::fflush(stdout);
                    return true;
                }
            }

            // Moving the sender means restarting the engine -- the transmit
            // sockets are bound to their group when they are opened, so there is
            // nothing to retune in place. That restart is confirmed rather than
            // assumed: a controller reads a 200 here as "the sender has moved",
            // and if the engine did not come back up on the new group then 200
            // is a lie it will not find out about.
            // Not `using namespace std::chrono` here: the local `seconds`
            // holds --seconds and would shadow std::chrono::seconds.
            const auto deadline =
                std::chrono::steady_clock::now() + std::chrono::seconds(10);
            for (;;) {
                const ReplayStatus s = engine.status();
                if (s.running) break;
                if (!engine.running()) {
                    err = s.error.empty() ? "the replay engine did not start" : s.error;
                    return false;
                }
                if (std::chrono::steady_clock::now() >= deadline) {
                    err = "the replay engine did not come up within 10 s";
                    return false;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }
            std::printf("[nmos] IS-05: sender enabled -> %s:%u\n",
                        want.destIpA.c_str(), unsigned(want.destPortA));
            std::fflush(stdout);
            return true;
        });
        if (!node->start(n))
            std::printf("nmos failed: %s\n", node->status().error.c_str());
        else if (!quiet)
            std::printf("nmos node API: %s\n", node->status().nodeApiUrl.c_str());
    }

    bool engineStarted = false;
    if (idle && wantNmos) {
        std::printf("\nidle: registered, waiting for a controller to activate the "
                    "sender over IS-05\n");
    } else {
        if (idle)
            std::printf("\n--idle has no effect without --nmos; starting the replay\n");
        std::printf("\nreplaying to %s:%d%s%s\n", groupA.c_str(), port,
                    cfg.enablePathB ? " and " : "",
                    cfg.enablePathB ? groupB.c_str() : "");
        engine.start(cfg);
        engineStarted = true;
        // The node came up before the engine did, so its idea of master_enable
        // was seeded from a sender that was not yet running. Tell it the engine
        // is live, or an IS-05 PATCH that moves the destination without naming
        // master_enable will activate that stale false and stop the sender
        // instead of moving it.
        if (wantNmos) node->notifyChanged();
    }

    double lastReport = -1.0;
    for (;;) {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));

        if (g_stop.load(std::memory_order_relaxed)) {
            std::printf("\n%s: stopping\n", signalName(g_signal.load()));
            break;
        }

        const ReplayStatus s = engine.status();
        if (s.running) engineStarted = true;

        // A fatal engine error ends the run either way: there is nothing left
        // to serve, and a node advertising a sender that cannot transmit is
        // worse than no node.
        if (!s.running && !s.error.empty()) {
            std::printf("stopped: %s\n", s.error.c_str());
            break;
        }
        // `completed` means --seconds elapsed, and nothing else.
        if (!s.running && s.completed) {
            std::printf("finished: reached %.0f s\n", seconds);
            break;
        }
        // With no node, the engine stopping is the end of the job.
        //
        // With one, this process is a service and must outlive the engine. A
        // controller may disable the sender over IS-05 and enable it again
        // later, and -- less obviously -- every IS-05 destination change stops
        // and restarts the engine, because the transmit sockets are bound to
        // their group when they are opened. Exiting on a transiently stopped
        // engine meant the process quit the instant it was routed, taking the
        // node out of the registry at the exact moment a controller had just
        // been told the move succeeded.
        if (!s.running && !wantNmos && engineStarted) break;

        if (reportInterval > 0.0 && s.running &&
            s.elapsedSeconds - lastReport >= reportInterval) {
            std::printf("  %5.1fs  %8.0f pkt/s (%.0f%%)  %6.0f Mb/s  frames %s  "
                        "ring %d/%d  repeats %s  loops %llu/%llu\n",
                        s.elapsedSeconds, s.achievedPps,
                        s.targetPps > 0 ? 100.0 * s.achievedPps / s.targetPps : 0.0,
                        s.wireMbps, commas(s.frameIndex).c_str(),
                        s.source.ringFill, s.source.ringDepth,
                        commas(s.repeatedFrames).c_str(),
                        (unsigned long long)s.source.loops,
                        (unsigned long long)s.source.earlyLoops);
            if (!s.warning.empty()) std::printf("  !! %s\n", s.warning.c_str());
            std::fflush(stdout);
            lastReport = s.elapsedSeconds;
        }
    }

    // Order matters. The node goes down first so the registry is told before the
    // stream stops, rather than a controller seeing a registered sender that has
    // already gone quiet.
    node->stop();
    engine.stop();
    stats.stop();
    return 0;
}
