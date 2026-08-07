#include "pcapreplay/pcap_source.h"

#include <algorithm>
#include <chrono>
#include <cstring>

#include "pcapreplay/bitpack.h"
#include "pcapreplay/hbrmt.h"
#include "pcapreplay/pcap_reader.h"
#include "pcapreplay/sdi_raster.h"

namespace pcapreplay {
namespace {

using Clock = std::chrono::steady_clock;

// Map a 16-bit RTP sequence to the absolute value nearest `near`.
//
// A 10-second 1080i25 capture wraps the 16-bit sequence about 20 times, so
// every comparison has to happen on an unwrapped counter. Unwrapping each leg
// independently would give the two legs different epochs; resolving against a
// shared cursor instead puts both in one absolute space with no epoch tracking
// at all, and is exact as long as the two captures are within 32768 datagrams
// (~0.24 s at 1080i25) of each other, which two legs of the same -7 pair always
// are.
inline std::uint64_t absNear(std::uint16_t raw, std::uint64_t near) {
    const std::int16_t delta = std::int16_t(raw - std::uint16_t(near));
    return std::uint64_t(std::int64_t(near) + delta);
}

// One capture leg: streams packets forward, keeping a bounded window of them
// keyed by absolute sequence so the merge can look either leg up.
class MergeLeg {
public:
    bool open(const std::string& path, int window, std::string& err) {
        window_ = window;
        mask_   = std::size_t(window - 1);          // window is a power of two
        pool_.assign(std::size_t(window) * kHbrmtPayloadBytes, 0);
        seqAt_.assign(std::size_t(window), 0);
        valid_.assign(std::size_t(window), 0);
        marker_.assign(std::size_t(window), 0);
        if (!rd_.open(path)) { err = rd_.error; return false; }
        return true;
    }

    bool isOpen() const { return rd_.isOpen(); }
    bool atEof()  const { return eof_; }
    std::uint64_t bytesRead() const { return rd_.bytesRead; }
    double progress() const { return rd_.progress(); }
    std::uint32_t dst() const { return dst_; }
    const HbrmtHeader& hbrmt() const { return hbrmt0_; }
    bool sawAny() const { return sawAny_; }

    void rewind() {
        rd_.rewindToFirstPacket();
        std::fill(valid_.begin(), valid_.end(), std::uint8_t(0));
        eof_ = false;
        haveLast_ = false;
        lastSeq_ = 0;
    }

    // Read forward until this leg has passed `cursor`, so that if the datagram
    // exists in the file it is now in the window. `anchor` seeds the absolute
    // space for the very first packet -- for the second leg that is the other
    // leg's cursor, which is what puts both into one numbering.
    void fill(std::uint64_t cursor, std::uint64_t anchor, bool haveAnchor) {
        while (!eof_) {
            if (haveLast_ && lastSeq_ > cursor) return;
            if (!readOne(haveLast_ ? lastSeq_ : (haveAnchor ? anchor : 0),
                         haveLast_ || haveAnchor))
                return;
        }
    }

    // Nothing more can arrive at or above `cursor`.
    bool drained(std::uint64_t cursor) const {
        return eof_ && (!haveLast_ || lastSeq_ <= cursor);
    }

    const std::uint8_t* find(std::uint64_t seq, bool& marker) const {
        const std::size_t i = std::size_t(seq) & mask_;
        if (!valid_[i] || seqAt_[i] != seq) return nullptr;
        marker = marker_[i] != 0;
        return pool_.data() + i * kHbrmtPayloadBytes;
    }

    std::uint64_t firstSeq() const { return firstSeq_; }
    bool haveFirst() const { return haveFirst_; }

private:
    // Returns false at EOF. `near` seeds the wrap resolution for this packet.
    bool readOne(std::uint64_t near, bool haveNear) {
        for (;;) {
            if (!rd_.next(pkt_)) { eof_ = true; return false; }

            UdpView u;
            if (!parseUdp(pkt_.data(), pkt_.size(), u, rd_.linktype)) continue;

            ParsedDatagram pd{};
            if (!parseDatagram({u.payload, u.len}, pd)) continue;
            if (pd.payload.size() != kHbrmtPayloadBytes) continue;

            // Lock to the first stream seen. A capture can hold more than one.
            if (!dst_) {
                dst_    = u.dstIp;
                hbrmt0_ = pd.hbrmt;
                sawAny_ = true;
            }
            if (u.dstIp != dst_) continue;

            const std::uint64_t s =
                haveNear ? absNear(pd.rtp.sequence, near) : pd.rtp.sequence;
            if (!haveFirst_) { haveFirst_ = true; firstSeq_ = s; }

            const std::size_t i = std::size_t(s) & mask_;
            std::memcpy(pool_.data() + i * kHbrmtPayloadBytes,
                        pd.payload.data(), kHbrmtPayloadBytes);
            seqAt_[i]  = s;
            valid_[i]  = 1;
            marker_[i] = pd.rtp.marker ? 1 : 0;

            lastSeq_  = s;
            haveLast_ = true;
            return true;
        }
    }

    PcapReader                 rd_;
    std::vector<std::uint8_t>  pool_;
    std::vector<std::uint64_t> seqAt_;
    std::vector<std::uint8_t>  valid_, marker_;
    std::vector<std::uint8_t>  pkt_;
    std::size_t   mask_ = 0;
    int           window_ = 0;
    std::uint32_t dst_ = 0;
    HbrmtHeader   hbrmt0_{};
    std::uint64_t lastSeq_ = 0, firstSeq_ = 0;
    bool haveLast_ = false, haveFirst_ = false, eof_ = false, sawAny_ = false;
};

int roundUpPow2(int v, int lo, int hi) {
    v = std::clamp(v, lo, hi);
    int p = lo;
    while (p < v) p <<= 1;
    return std::min(p, hi);
}

// Read the first usable datagram of a file, for probe() and for identifying the
// format before the producer thread starts.
bool sniff(const std::string& path, HbrmtHeader& hb, std::uint32_t& dst,
           std::uint64_t& fileBytes, std::string& err) {
    PcapReader rd;
    if (!rd.open(path)) { err = rd.error; return false; }
    fileBytes = rd.fileBytes;
    std::vector<std::uint8_t> pkt;
    std::uint64_t looked = 0;
    while (rd.next(pkt)) {
        // A capture can open with ARP, IGMP or another stream entirely; give it
        // a reasonable run before declaring there is no ST 2022-6 in here.
        if (++looked > 200000) break;
        UdpView u;
        if (!parseUdp(pkt.data(), pkt.size(), u, rd.linktype)) continue;
        ParsedDatagram pd{};
        if (!parseDatagram({u.payload, u.len}, pd)) continue;
        if (pd.payload.size() != kHbrmtPayloadBytes) continue;
        hb  = pd.hbrmt;
        dst = u.dstIp;
        return true;
    }
    err = path + ": no ST 2022-6 datagrams found";
    return false;
}

}  // namespace

// ---------------------------------------------------------------------------

PcapSource::~PcapSource() { stop(); }

PcapProbe PcapSource::probe(const std::string& fileRed, const std::string& fileBlue) {
    PcapProbe p;
    if (fileRed.empty() && fileBlue.empty()) {
        p.error = "pick a red and/or blue capture";
        return p;
    }
    // Either leg alone is a valid source; if only blue is given it simply
    // becomes the primary.
    const std::string& primary = fileRed.empty() ? fileBlue : fileRed;

    HbrmtHeader hb{};
    std::uint32_t dst = 0;
    if (!sniff(primary, hb, dst, p.redBytes, p.error)) return p;

    p.format = formatFromHbrmtCodes(hb.frame, hb.frate, hb.sample);
    if (p.format == SdiFormat::Unknown) {
        char buf[160];
        std::snprintf(buf, sizeof buf,
                      "unsupported video format (HBRMT FRAME=0x%02X FRATE=0x%02X "
                      "SAMPLE=0x%02X)", hb.frame, hb.frate, hb.sample);
        p.error = buf;
        return p;
    }
    p.formatText  = formatDescription(p.format);
    p.redAddress  = ipStr(dst);

    if (!fileRed.empty() && !fileBlue.empty()) {
        HbrmtHeader hb2{};
        std::uint32_t dst2 = 0;
        std::string err2;
        if (!sniff(fileBlue, hb2, dst2, p.blueBytes, err2)) {
            p.warning = "blue leg unusable, replaying red only -- " + err2;
        } else if (formatFromHbrmtCodes(hb2.frame, hb2.frate, hb2.sample) != p.format) {
            p.warning = "blue leg is " +
                        formatDescription(formatFromHbrmtCodes(hb2.frame, hb2.frate,
                                                               hb2.sample)) +
                        " but red is " + p.formatText + " -- refusing to merge";
        } else {
            p.blueAddress = ipStr(dst2);
            if (dst2 == dst)
                p.warning = "both legs carry " + p.redAddress +
                            " -- this looks like the same capture twice";
        }
    }

    // Qualified: PcapSource has a formatInfo() member that would otherwise hide
    // the free function.
    const SdiFormatInfo& fi = ::pcapreplay::formatInfo(p.format);
    const double dgPerFrame =
        double((fi.bytesPerFrame() + std::int64_t(kHbrmtPayloadBytes) - 1) /
               std::int64_t(kHbrmtPayloadBytes));
    // Wire bytes per datagram: 1400 UDP payload + 8 UDP + 20 IP + 14 Ethernet,
    // plus the 16-byte pcap record header.
    const double perPacket = double(kDatagramBytes) + 8 + 20 + 14 + 16;
    p.estimatedSeconds =
        double(p.redBytes) / perPacket / (dgPerFrame * fi.frameRate());
    p.ok = true;
    return p;
}

bool PcapSource::start(const PcapSourceConfig& cfg) {
    stop();
    {
        std::lock_guard<std::mutex> lk(mutexStatus_);
        status_ = PcapSourceStatus{};
    }

    const PcapProbe p = probe(cfg.fileRed, cfg.fileBlue);
    if (!p.ok) {
        std::lock_guard<std::mutex> lk(mutexStatus_);
        status_.error = p.error;
        return false;
    }

    fi_         = ::pcapreplay::formatInfo(p.format);
    frameBytes_ = std::size_t(fi_.bytesPerFrame());
    depth_      = std::clamp(cfg.ringFrames, 2, 240);
    ring_.assign(std::size_t(depth_) * frameBytes_, 0);
    head_ = tail_ = count_ = 0;
    checkedOut_ = false;

    {
        std::lock_guard<std::mutex> lk(mutexStatus_);
        status_.running    = true;
        status_.format     = p.format;
        status_.formatText = p.formatText;
        status_.warning    = p.warning;
        status_.redAddress = p.redAddress;
        status_.blueAddress = p.blueAddress;
        status_.ringDepth  = depth_;
    }

    stopping_.store(false, std::memory_order_relaxed);
    running_.store(true, std::memory_order_relaxed);
    thread_ = std::thread(&PcapSource::run, this, cfg);
    return true;
}

void PcapSource::stop() {
    stopping_.store(true, std::memory_order_relaxed);
    notFull_.notify_all();
    notEmpty_.notify_all();
    if (thread_.joinable()) thread_.join();
    running_.store(false, std::memory_order_relaxed);
    std::lock_guard<std::mutex> lk(mutexStatus_);
    status_.running = false;
}

const std::uint8_t* PcapSource::next(int timeoutMs, bool& repeated) {
    repeated = false;
    std::unique_lock<std::mutex> lk(mutex_);

    // A checked-out frame still occupies its slot, so "another one is ready"
    // means there is a filled slot beyond it.
    auto spare = [this] { return count_ - (checkedOut_ ? 1 : 0); };
    const bool got = notEmpty_.wait_for(
        lk, std::chrono::milliseconds(timeoutMs),
        [&] { return spare() > 0 || stopping_.load(std::memory_order_relaxed); });

    if (!got || spare() <= 0) {
        if (!checkedOut_) return nullptr;
        repeated = true;
        lk.unlock();
        std::lock_guard<std::mutex> sl(mutexStatus_);
        ++status_.starves;
        return ring_.data() + std::size_t(tail_) * frameBytes_;
    }

    if (checkedOut_) {                       // retire the frame just finished
        tail_ = (tail_ + 1) % depth_;
        --count_;
        lk.unlock();
        notFull_.notify_one();
        lk.lock();
    }
    checkedOut_ = true;
    return ring_.data() + std::size_t(tail_) * frameBytes_;
}

void PcapSource::releaseAll() {
    {
        std::lock_guard<std::mutex> lk(mutex_);
        if (!checkedOut_) return;
        checkedOut_ = false;
        tail_ = (tail_ + 1) % depth_;
        --count_;
    }
    notFull_.notify_one();
}

PcapSourceStatus PcapSource::status() const {
    std::lock_guard<std::mutex> lk(mutexStatus_);
    PcapSourceStatus s = status_;
    {
        std::lock_guard<std::mutex> rl(mutex_);
        s.ringFill  = count_;
        s.ringDepth = depth_;
    }
    return s;
}

// ---------------------------------------------------------------------------

void PcapSource::run(PcapSourceConfig cfg) {
    auto fail = [&](const std::string& msg) {
        std::lock_guard<std::mutex> lk(mutexStatus_);
        status_.error   = msg;
        status_.running = false;
        running_.store(false, std::memory_order_relaxed);
        notEmpty_.notify_all();
    };
    auto warn = [&](const std::string& msg) {
        std::lock_guard<std::mutex> lk(mutexStatus_);
        status_.warning = msg;
    };

    const int window = roundUpPow2(cfg.mergeWindow, 1024, 65536);

    // Only blue given is still a single-leg replay; make it the primary.
    const std::string redPath  = cfg.fileRed.empty() ? cfg.fileBlue : cfg.fileRed;
    const std::string bluePath = cfg.fileRed.empty() ? std::string() : cfg.fileBlue;

    MergeLeg A, B;
    std::string err;
    if (!A.open(redPath, window, err)) { fail(err); return; }

    bool haveB = false;
    if (!bluePath.empty()) {
        std::string errB;
        if (!B.open(bluePath, window, errB))
            warn("blue leg unusable, replaying red only -- " + errB);
        else
            haveB = true;
    }
    {
        std::lock_guard<std::mutex> lk(mutexStatus_);
        status_.merging = haveB;
    }

    const int lineWords = fi_.totalSamples * 2;
    const bool hd = fi_.isHd;

    // Frame validation, as in sdi_extract. A frame cut on the marker bit starts
    // at byte phase 0, so the raster can be checked directly.
    //
    // HD carries a line number in the EAV and is checked against it. SD (ST 259)
    // carries none, so it is validated on structure instead: an EAV on every
    // line and exactly two falling edges of the V bit -- one per field -- which
    // pins the vertical timing just as firmly.
    std::uint16_t probeWords[16];
    auto rasterOk = [&](const std::uint8_t* p) {
        int vFalls = 0;
        bool prevV = true;
        for (int ln = 1; ln <= fi_.totalLines; ++ln) {
            const std::size_t atWord = std::size_t(ln - 1) * lineWords;
            unpack10(p + atWord / 4 * 5, 16, probeWords);
            if (hd) {
                if (!(probeWords[0] == 0x3FF && probeWords[1] == 0x3FF &&
                      probeWords[2] == 0 && probeWords[3] == 0 &&
                      probeWords[4] == 0 && probeWords[5] == 0))
                    return false;
                if (lineNumberFromWords(probeWords[8], probeWords[10]) != ln)
                    return false;
            } else {
                if (!(probeWords[0] == 0x3FF && probeWords[1] == 0 &&
                      probeWords[2] == 0 && (probeWords[3] & 0x040) &&
                      (probeWords[3] & 0x200)))
                    return false;
                const bool v = (probeWords[3] & 0x080) != 0;
                if (prevV && !v) ++vFalls;
                prevV = v;
            }
        }
        return hd || vFalls == 2;
    };

    std::vector<std::uint8_t> cur;
    cur.reserve(frameBytes_ + kHbrmtPayloadBytes * 2);

    std::uint64_t cursor = 0;
    bool anchored = false;
    bool collecting = false;
    int  consecutiveBad = 0;

    std::uint64_t produced = 0, rejRaster = 0, rejShort = 0, rejHole = 0;
    std::uint64_t holes = 0, filledB = 0, loops = 0, earlyLoops = 0;

    auto restart = [&](bool early, const std::string& why) {
        A.rewind();
        if (haveB) B.rewind();
        cursor = 0;
        anchored = false;
        collecting = false;
        consecutiveBad = 0;
        cur.clear();
        if (early) { ++earlyLoops; warn(why); }
        else       { ++loops; }
    };

    auto publish = [&](double readMbps, double progress) {
        std::lock_guard<std::mutex> lk(mutexStatus_);
        status_.framesProduced       = produced;
        status_.framesRejectedRaster = rejRaster;
        status_.framesRejectedShort  = rejShort;
        status_.framesRejectedHole   = rejHole;
        status_.sequenceHoles        = holes;
        status_.filledFromBlue       = filledB;
        status_.loops                = loops;
        status_.earlyLoops           = earlyLoops;
        status_.readMbps             = readMbps;
        status_.progress             = progress;
    };

    auto lastReport = Clock::now();
    std::uint64_t lastBytes = 0;

    // Push a completed frame, blocking while the ring is full. Returns false if
    // the source is stopping.
    auto push = [&](const std::uint8_t* frame) {
        std::unique_lock<std::mutex> lk(mutex_);
        notFull_.wait(lk, [this] {
            return count_ < depth_ || stopping_.load(std::memory_order_relaxed);
        });
        if (stopping_.load(std::memory_order_relaxed)) return false;
        std::memcpy(ring_.data() + std::size_t(head_) * frameBytes_, frame, frameBytes_);
        head_ = (head_ + 1) % depth_;
        ++count_;
        lk.unlock();
        notEmpty_.notify_one();
        return true;
    };

    while (!stopping_.load(std::memory_order_relaxed)) {
        // Keep both legs just ahead of the cursor.
        A.fill(cursor, 0, anchored);
        if (!anchored) {
            if (!A.haveFirst()) {
                // Nothing usable in the whole file. probe() already passed, so
                // this only happens on an empty rewind; treat as fatal.
                fail("red leg: no ST 2022-6 datagrams found");
                return;
            }
            cursor = A.firstSeq();
            anchored = true;
            A.fill(cursor, 0, true);
        }
        if (haveB) B.fill(cursor, cursor, true);

        bool marker = false;
        const std::uint8_t* data = A.find(cursor, marker);
        if (!data && haveB) {
            data = B.find(cursor, marker);
            if (data) ++filledB;
        }

        if (!data) {
            // End of the capture, or a datagram neither leg carries.
            if (A.drained(cursor) && (!haveB || B.drained(cursor))) {
                if (produced == 0) {
                    fail("no usable frames in the capture -- wrong format, or "
                         "the stream is not frame-aligned on the RTP marker bit");
                    return;
                }
                restart(false, {});
                continue;
            }
            ++holes;
            if (collecting) { ++rejHole; ++consecutiveBad; }
            collecting = false;
            cur.clear();
            ++cursor;
            if (consecutiveBad >= cfg.skipTolerance) {
                restart(true, "capture ran out of usable frames after " +
                              std::to_string(cfg.skipTolerance) +
                              " consecutive failures -- looped early");
            }
            continue;
        }

        if (collecting) cur.insert(cur.end(), data, data + kHbrmtPayloadBytes);
        ++cursor;
        if (!marker) continue;

        if (collecting) {
            if (cur.size() >= frameBytes_) {
                if (rasterOk(cur.data())) {
                    if (!push(cur.data())) break;
                    ++produced;
                    consecutiveBad = 0;
                } else {
                    ++rejRaster;
                    ++consecutiveBad;
                }
            } else {
                ++rejShort;
                ++consecutiveBad;
            }
        }
        cur.clear();
        collecting = true;                 // the next datagram starts a frame

        if (consecutiveBad >= cfg.skipTolerance) {
            restart(true, "capture ran out of usable frames after " +
                          std::to_string(cfg.skipTolerance) +
                          " consecutive failures -- looped early");
            continue;
        }

        const auto now = Clock::now();
        const double dt = std::chrono::duration<double>(now - lastReport).count();
        if (dt >= 0.25) {
            const std::uint64_t total = A.bytesRead() + (haveB ? B.bytesRead() : 0);
            publish(double(total - lastBytes) * 8.0 / 1e6 / dt, A.progress());
            lastBytes = total;
            lastReport = now;
        }
    }

    publish(0.0, A.progress());
    {
        std::lock_guard<std::mutex> lk(mutexStatus_);
        status_.running = false;
    }
    running_.store(false, std::memory_order_relaxed);
    notEmpty_.notify_all();
}

}  // namespace pcapreplay
