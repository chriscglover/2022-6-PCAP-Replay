// Replay a pcap capture as a continuous ST 2022-6/-7 source.
//
// Frames arrive from PcapSource, which streams them off disk and merges the two
// -7 legs. This engine turns them back into datagrams: RTP sequence numbers,
// timestamps, SSRC and HBRMT frame counters are all generated fresh, so the loop
// join at the end of the capture is invisible and the stream runs indefinitely.
// That is the whole reason for re-originating rather than replaying the captured
// packets verbatim -- a verbatim replay has to jump all four of those backwards
// at every loop, which a receiver reads as a fault.
//
// The raster is copied through untouched apart from the timecode rewrite, so the
// replay still carries everything the broadcast did: ATC timecode, OP-47
// subtitles, SCTE 104, AFD, ST 2020 metadata and 16 channels of ST 299 audio.
//
// Same split as the original: the GUI owns configuration and display, this owns
// everything real, and it runs on its own thread.
#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>

#include "pcapreplay/net_multicast.h"
#include "pcapreplay/pcap_source.h"
#include "pcapreplay/sdi_format.h"

namespace pcapreplay {

struct ReplayPath {
    std::string   group = "239.1.1.1";
    std::uint16_t port  = 40000;
    std::string   interfaceIp;
};

// Impairments for exercising a receiver. All are random rather than periodic:
// a fixed 1-in-N pattern can line up with a receiver's own buffering and either
// flatter or unfairly punish it.
struct ReplayFaults {
    bool   lossA      = false;   // drop individual datagrams on path A
    bool   lossB      = false;   // ... and on path B, independently
    bool   burstLoss  = false;   // drop a short run, as a real glitch does
    bool   reorder    = false;   // swap adjacent datagrams
    bool   duplicate  = false;   // send a datagram twice
    bool   seqJump    = false;   // sequence discontinuity, as after a restart
    double ratePercent = 0.10;   // probability per datagram, per enabled fault

    bool any() const {
        return lossA || lossB || burstLoss || reorder || duplicate || seqJump;
    }
};

struct ReplayConfig {
    // Source. Either alone is a valid single-leg replay; both together are
    // merged, so a datagram lost on one leg is filled from the other.
    std::string  fileRed;
    std::string  fileBlue;
    int          ringFrames    = 16;
    int          skipTolerance = 10;

    // Transmit
    bool         enablePathB = false;   // false = ST 2022-6, true = ST 2022-7
    ReplayPath   pathA, pathB;
    int          ttl = 8;
    bool         loopback = true;
    bool         rewriteTimecode = true;
    int          ref = 3;               // HBRMT R field; real broadcast kit sends 3
    std::uint32_t ssrc = 0x20220006u;

    // Stop after this many seconds of transmit. 0 = run until stopped.
    double       maxSeconds = 0.0;

    ReplayFaults faults;
};

struct ReplayStatus {
    bool          running = false;
    bool          completed = false;     // hit maxSeconds and stopped cleanly
    std::string   error;
    std::string   warning;
    std::string   formatText;

    std::uint64_t frameIndex = 0;        // monotonic since Start
    double        elapsedSeconds = 0.0;

    std::uint64_t datagrams = 0;
    double        targetPps = 0.0;
    double        achievedPps = 0.0;
    double        wireMbps = 0.0;

    std::uint64_t droppedA = 0, droppedB = 0;
    std::uint64_t reordered = 0, duplicated = 0, seqJumps = 0;

    // Timecode being written into the stream right now.
    std::string   tod, countdown;
    int           atcPackets = 0;
    bool          crcModelOk = false;
    bool          rewritingTimecode = false;

    // Frames the transmitter had to repeat because the ring ran dry. Non-zero
    // means the disk is not keeping up with line rate.
    std::uint64_t repeatedFrames = 0;

    PcapSourceStatus source;
};

class ReplayEngine {
public:
    ReplayEngine() = default;
    ~ReplayEngine();
    ReplayEngine(const ReplayEngine&) = delete;
    ReplayEngine& operator=(const ReplayEngine&) = delete;

    bool  start(const ReplayConfig& cfg);
    void  stop();
    bool  running() const { return running_.load(std::memory_order_relaxed); }
    ReplayStatus status() const;

    // The configuration currently on the wire. NMOS IS-05 reports this as the
    // active transport parameters and builds the SDP from it.
    ReplayConfig activeConfig() const;

    // Inspect the chosen files without starting, so a GUI can describe a
    // selection as soon as it is made.
    static PcapProbe probe(const std::string& fileRed, const std::string& fileBlue) {
        return PcapSource::probe(fileRed, fileBlue);
    }

private:
    void run(ReplayConfig cfg);

    std::thread       thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};

    mutable std::mutex mutex_;
    ReplayStatus       status_;
    ReplayConfig       config_;
};

}  // namespace pcapreplay
