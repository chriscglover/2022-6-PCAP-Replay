// Streaming SDI frame source backed by one or two pcap captures.
//
// This replaces the .sdi file that NDI2022-6's replay engine loaded whole into
// RAM. Captures here are gigabytes, and the whole point is to replay all of one
// rather than the first few seconds, so frames are produced on a background
// thread straight off disk into a small ring buffer and consumed as they are
// packetised. Peak RAM is the ring depth, not the file size.
//
// What the producer thread does, per frame:
//
//   1. Pull the next datagram in RTP sequence order, taking it from the red leg
//      if it is there and the blue leg if it is not. That is the ST 2022-7
//      merge: a datagram lost on one leg is filled from the other, which is
//      exactly what the redundancy is for. With one file it degrades to a plain
//      read.
//   2. Cut frames on the RTP marker bit rather than by locking the raster.
//      Real broadcast kit zero-pads the last datagram of a frame -- 1080i25
//      sends 5397 x 1376 = 7,426,272 bytes for a 7,425,000-byte raster -- so the
//      10-bit byte phase shifts by 1272 mod 5 = 2 at every frame boundary and a
//      continuous-raster reader loses lock every frame. Keying on the marker
//      sidesteps it, and each frame then starts at byte phase 0.
//   3. Validate the raster (EAV on every line, and line numbers on HD) before
//      the frame is allowed into the ring.
//
// Frames that fail, or that have a sequence hole neither leg could fill, are
// dropped and the next one is tried. If `skipTolerance` frames in a row fail,
// the capture is treated as exhausted at that point: both readers rewind, the
// loop restarts early and a warning is published for the GUI. That stops a
// capture that turns to garbage part way through from stalling the output.
//
// The loop join needs no concealment. The replay engine generates RTP sequence
// numbers, timestamps, SSRC and HBRMT frame counters itself, so wrapping back to
// the top of the file is invisible on the wire -- unlike a verbatim packet
// replay, which has to jump all of them backwards and reads as a fault.
#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "pcapreplay/sdi_format.h"

namespace pcapreplay {

struct PcapSourceConfig {
    std::string fileRed;          // primary leg; required
    std::string fileBlue;         // second -7 leg; optional, enables the merge

    // Ring depth in frames. 1080i25 is 7.42 MB/frame, so 16 frames is ~119 MB
    // and about 0.64 s of slack against disk read jitter.
    int ringFrames = 16;

    // Consecutive unusable frames before the capture is treated as exhausted
    // and the loop restarts early.
    int skipTolerance = 10;

    // Per-leg reorder window, in datagrams. Only has to cover the skew between
    // the two captures plus any reordering within one; 8192 is ~61 ms at
    // 1080i25 and costs ~11 MB per leg.
    int mergeWindow = 8192;
};

struct PcapSourceStatus {
    bool        running = false;
    std::string error;            // fatal; the source has stopped
    std::string warning;          // non-fatal, e.g. an early loop

    SdiFormat   format = SdiFormat::Unknown;
    std::string formatText;
    bool        merging = false;  // both legs supplied and carrying data
    std::string redAddress, blueAddress;

    std::uint64_t framesProduced   = 0;
    std::uint64_t framesRejectedRaster = 0;
    std::uint64_t framesRejectedShort  = 0;
    std::uint64_t framesRejectedHole   = 0;
    std::uint64_t sequenceHoles    = 0;   // missing on both legs
    std::uint64_t filledFromBlue   = 0;   // missing on red, recovered from blue
    std::uint64_t loops            = 0;   // full passes over the capture
    std::uint64_t earlyLoops       = 0;   // restarts triggered by skipTolerance

    double        progress = 0.0;         // 0..1 through the current pass
    double        readMbps = 0.0;
    int           ringFill = 0;
    int           ringDepth = 0;
    std::uint64_t starves = 0;            // consumer found the ring empty
};

// Result of inspecting the files without starting a replay, so the GUI can
// describe a selection as soon as it is made.
struct PcapProbe {
    bool          ok = false;
    std::string   error;
    std::string   warning;
    SdiFormat     format = SdiFormat::Unknown;
    std::string   formatText;
    std::string   redAddress, blueAddress;
    std::uint64_t redBytes = 0, blueBytes = 0;
    // Estimated, from file size and the nominal datagram rate: exact frame
    // counts would mean reading the whole capture, which is the thing this
    // design exists to avoid.
    double        estimatedSeconds = 0.0;
};

class PcapSource {
public:
    PcapSource() = default;
    ~PcapSource();
    PcapSource(const PcapSource&) = delete;
    PcapSource& operator=(const PcapSource&) = delete;

    // Read just enough of each file to identify the format and the multicast
    // group each leg carries. Cheap: stops at the first valid datagram.
    static PcapProbe probe(const std::string& fileRed, const std::string& fileBlue);

    // Opens both files and identifies the format synchronously, so a bad path
    // or an unsupported format is reported here rather than appearing as a
    // status error a moment later. Returns false and fills status().error.
    bool start(const PcapSourceConfig& cfg);
    void stop();
    bool running() const { return running_.load(std::memory_order_relaxed); }

    // Advance to the next frame.
    //
    // If none is ready within the timeout, the frame already checked out stays
    // checked out and is returned again with `repeated` set. That is deliberate:
    // a transmitter that stalls because the disk hiccupped produces a gap on the
    // wire, which a receiver reads as a fault, whereas repeating a frame keeps
    // the packet rate and the RTP sequence continuous. The starve counter makes
    // it visible rather than silent.
    //
    // Returns nullptr only when nothing has ever been checked out and none
    // arrived, or the source is stopping.
    const std::uint8_t* next(int timeoutMs, bool& repeated);

    // Give back the checked-out frame, if any. Call before stop().
    void releaseAll();

    std::size_t          frameBytes()  const { return frameBytes_; }
    const SdiFormatInfo& formatInfo()  const { return fi_; }

    PcapSourceStatus status() const;

private:
    void run(PcapSourceConfig cfg);

    // Producer-side helpers live in the .cpp; the ring is the only shared state.
    std::thread       thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};

    // Ring of whole frames. Producer writes slot head_, consumer reads tail_.
    // count_ is the number of filled slots and *includes* a checked-out frame,
    // which is what stops the producer from overwriting one still being
    // transmitted.
    std::vector<std::uint8_t> ring_;          // depth * frameBytes_
    int           depth_      = 0;
    std::size_t   frameBytes_ = 0;
    SdiFormatInfo fi_{};

    mutable std::mutex      mutex_;
    std::condition_variable notEmpty_, notFull_;
    int  head_ = 0, tail_ = 0, count_ = 0;
    bool checkedOut_ = false;

    mutable std::mutex mutexStatus_;
    PcapSourceStatus   status_;
};

}  // namespace pcapreplay
