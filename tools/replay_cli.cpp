// Console driver for the same engines the GUI uses.
//
// Exists so the streaming ingest, the ST 2022-7 merge and the NMOS node can be
// exercised and measured without a dialog box in the way -- and so a replay can
// be scripted.
//
//   replay_cli <red.pcap> [blue.pcap] [options]
//
//     --probe            identify the capture(s) and exit
//     --gaps             walk one capture packet by packet and report where its
//                        RTP sequence actually jumps. Independent of the merge,
//                        so it settles whether a hole count comes from the file
//                        or from the reader.
//     --ingest N         run the source alone for N seconds, no transmit.
//                        Measures how fast frames can be produced off disk,
//                        which is the thing that decides whether a capture can
//                        be replayed at line rate at all.
//     --group A          path A destination        (default 239.1.1.1)
//     --group-b B        path B destination, enables ST 2022-7 transmit
//     --port N           destination port          (default 40000)
//     --iface IP         outgoing interface for both paths
//     --seconds N        stop after N seconds
//     --ring N           ring buffer depth, frames (default 16)
//     --skip N           consecutive bad frames before looping (default 10)
//     --no-timecode      leave the ATC packets alone
//     --nmos             register as an NMOS sender
//     --nmos-port N      node API port             (default 3210)
//     --registry H:P     registry override, skips mDNS discovery
//     --sdp              print the SDP that NMOS would publish, and exit

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

#include "pcapreplay/hbrmt.h"
#include "pcapreplay/net_interfaces.h"
#include "pcapreplay/net_multicast.h"
#include "pcapreplay/pcap_reader.h"
#include "pcapreplay/pcap_source.h"
#include "pcapreplay/replay_engine.h"
#include "pcapreplay/nmos/http.h"
#include "pcapreplay/nmos/nmos_node.h"

using namespace pcapreplay;

namespace {

std::string commas(std::uint64_t v) {
    std::string s = std::to_string(v);
    for (int i = int(s.size()) - 3; i > 0; i -= 3) s.insert(std::size_t(i), ",");
    return s;
}

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

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf(
            "usage: replay_cli <red.pcap> [blue.pcap] [options]\n"
            "  --probe  --ingest N  --sdp\n"
            "  --group A  --group-b B  --port N  --iface IP  --seconds N\n"
            "  --ring N  --skip N  --no-timecode\n"
            "  --nmos  --nmos-port N  --registry HOST:PORT\n");
        return 2;
    }

    std::string red, blue;
    std::string groupA = "239.1.1.1", groupB, iface;
    int  port = 40000, ring = 16, skip = 10, nmosPort = 3210;
    double seconds = 0.0, ingestSeconds = 0.0;
    bool probeOnly = false, timecode = true, wantNmos = false, wantSdp = false;
    bool wantGaps = false;
    std::string registry;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto val = [&]() -> std::string { return i + 1 < argc ? argv[++i] : ""; };
        if      (a == "--probe")       probeOnly = true;
        else if (a == "--gaps")        wantGaps = true;
        else if (a == "--ingest")      ingestSeconds = std::atof(val().c_str());
        else if (a == "--sdp")         wantSdp = true;
        else if (a == "--group")       groupA = val();
        else if (a == "--group-b")     groupB = val();
        else if (a == "--port")        port = std::atoi(val().c_str());
        else if (a == "--iface")       iface = val();
        else if (a == "--seconds")     seconds = std::atof(val().c_str());
        else if (a == "--ring")        ring = std::atoi(val().c_str());
        else if (a == "--skip")        skip = std::atoi(val().c_str());
        else if (a == "--no-timecode") timecode = false;
        else if (a == "--nmos")        wantNmos = true;
        else if (a == "--nmos-port")   nmosPort = std::atoi(val().c_str());
        else if (a == "--registry")    registry = val();
        else if (!a.empty() && a[0] != '-') {
            if (red.empty()) red = a; else blue = a;
        } else {
            std::printf("unknown option %s\n", a.c_str());
            return 2;
        }
    }

    WinsockScope ws;

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

        while (rd.next(pkt)) {
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
    cfg.pathB.interfaceIp = iface;
    cfg.rewriteTimecode = timecode;
    cfg.maxSeconds = seconds;

    std::unique_ptr<nmos::NmosBackend> node(nmos::createBuiltinBackend());
    ReplayEngine engine;

    auto query = [&]() {
        nmos::SenderTransport t;
        t.active     = engine.running();
        t.redundant  = cfg.enablePathB;
        t.sourceIpA  = iface;
        t.sourceIpB  = iface;
        t.destIpA    = cfg.pathA.group;
        t.destPortA  = cfg.pathA.port;
        t.destIpB    = cfg.pathB.group;
        t.destPortB  = cfg.pathB.port;
        t.ttl        = cfg.ttl;
        t.ssrc       = cfg.ssrc;
        t.interfaceNameA = iface.empty() ? "eth0" : iface;
        t.interfaceNameB = iface.empty() ? "eth0" : iface;
        for (const auto& ni : enumerateInterfaces())
            if (ni.ipv4 == iface) { t.macA = ni.mac; t.macB = ni.mac; }
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

    if (wantNmos) {
        nmos::NmosConfig n;
        n.enabled  = true;
        n.nodeIp   = iface;
        n.nodePort = std::uint16_t(nmosPort);
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
            cfg.pathA.group = want.destIpA;
            cfg.pathA.port  = want.destPortA;
            if (cfg.enablePathB) {
                cfg.pathB.group = want.destIpB;
                cfg.pathB.port  = want.destPortB;
            }
            if (want.active) {
                if (!isValidMulticastGroup(cfg.pathA.group)) {
                    err = "destination_ip is not a usable multicast group";
                    return false;
                }
                engine.start(cfg);
            } else {
                engine.stop();
            }
            std::printf("[nmos] IS-05 activation: %s -> %s:%u\n",
                        want.active ? "enable" : "disable",
                        cfg.pathA.group.c_str(), cfg.pathA.port);
            return true;
        });
        if (!node->start(n))
            std::printf("nmos failed: %s\n", node->status().error.c_str());
        else
            std::printf("\nnmos node API: %s\n", node->status().nodeApiUrl.c_str());
    }

    std::printf("\nreplaying to %s:%d%s%s\n", groupA.c_str(), port,
                cfg.enablePathB ? " and " : "",
                cfg.enablePathB ? groupB.c_str() : "");
    engine.start(cfg);

    double lastReport = -1.0;
    for (;;) {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        const ReplayStatus s = engine.status();
        if (!s.running && !s.error.empty()) {
            std::printf("stopped: %s\n", s.error.c_str());
            break;
        }
        if (!s.running && s.completed) {
            std::printf("finished: reached %.0f s\n", seconds);
            break;
        }
        if (!s.running && lastReport >= 0.0) break;
        if (s.elapsedSeconds - lastReport >= 2.0) {
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
            lastReport = s.elapsedSeconds;
        }
    }

    engine.stop();
    node->stop();
    return 0;
}
