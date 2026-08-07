#include "pcapreplay/replay_engine.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <mutex>
#include <vector>

#include "pcapreplay/bitpack.h"
#include "pcapreplay/crc.h"
#include "pcapreplay/hbrmt.h"
#include "pcapreplay/pacer.h"
#include "pcapreplay/sdi_raster.h"

namespace pcapreplay {
namespace {

// ---- ATC timecode rewriting -------------------------------------------------
//
// A looping capture loops its timecode, which makes it useless for judging how
// long a soak test has run. Rewriting per frame gives real time of day on the
// TOD packets and a genuine countdown to midnight on the outlier.
//
// Touching a user word means repairing three things or a conformant receiver
// rejects the line: the word's own parity (b8 even, b9 = !b8), the ST 291 packet
// checksum, and the ST 292 line CRC-18. The CRC is the subtle one -- the CRC
// covering a VANC packet lives in the FOLLOWING line's header, because it spans
// the active samples preceding the EAV it sits behind.
//
// Streaming changes one thing from the original: frames are no longer a fixed
// cyclic buffer that could be scanned once at load. The site positions are
// learnt from the first frame and then reused, with a cheap DID/SDID check per
// site per frame and a rescan if the layout moves.

struct AtcSite {
    std::size_t  udwWord = 0;    // absolute word index of the first user word
    std::size_t  didWord = 0;
    int          line = 0;
    int          dc = 0;
    bool         countdown = false;
    std::int64_t firstValue = 0;
};

std::int64_t atcToFrames(int h, int m, int s, int f, int fps) {
    return (std::int64_t(h) * 3600 + std::int64_t(m) * 60 + s) * fps + f;
}

void framesToFields(std::int64_t frames, int fps, int& h, int& m, int& s, int& f) {
    if (frames < 0) frames = 0;
    f = int(frames % fps); frames /= fps;
    s = int(frames % 60);  frames /= 60;
    m = int(frames % 60);  frames /= 60;
    h = int(frames % 24);
}

// The timecode nibble sits in b7..b4; the low nibbles carry the binary groups
// and are preserved.
void writeAtc(std::uint16_t* udw, int h, int m, int s, int f) {
    auto put = [&](int i, int v) {
        const std::uint16_t keep = std::uint16_t(udw[i] & 0x0F);
        udw[i] = withNotB8(std::uint16_t((std::uint16_t(v & 0x0F) << 4) | keep));
    };
    put(0, f % 10);   put(2,  (f / 10) & 0x03);
    put(4, s % 10);   put(6,  (s / 10) & 0x07);
    put(8, m % 10);   put(10, (m / 10) & 0x07);
    put(12, h % 10);  put(14, (h / 10) & 0x03);
}

std::int64_t readAtc(const std::uint16_t* udw, int fps) {
    auto n = [&](int i) { return (udw[std::size_t(i) * 2] >> 4) & 0x0F; };
    return atcToFrames(n(12) + (n(14) & 0x3) * 10, n(8) + (n(10) & 0x7) * 10,
                       n(4) + (n(6) & 0x7) * 10,  n(0) + (n(2) & 0x3) * 10, fps);
}

std::string hmsf(std::int64_t frames, int fps) {
    int h, m, s, f;
    framesToFields(frames, fps, h, m, s, f);
    char buf[16];
    std::snprintf(buf, sizeof buf, "%02d:%02d:%02d:%02d", h, m, s, f);
    return buf;
}

class AtcRewriter {
public:
    void reset(const SdiFormatInfo& fi, std::size_t frameBytes) {
        fi_          = fi;
        frameBytes_  = frameBytes;
        lineWords_   = fi.totalSamples * 2;
        activeWords_ = fi.activeWidth * 2;
        fps_         = int(fi.frameRate() + 0.5);
        // ST 292 CRC coverage, per stream: the active samples plus the four EAV
        // words and the two line-number words. 1926 for 1080-line formats.
        crcWords_    = std::size_t(fi.activeWidth + 6);
        sites_.clear();
        crcOk_ = false;
        classified_ = false;
        missStreak_ = 0;
    }

    int  siteCount() const { return int(sites_.size()); }
    bool crcOk()     const { return crcOk_; }
    bool classified() const { return classified_; }

    // Full scan. Only HD carries ATC in a form we rewrite.
    void discover(const std::uint8_t* frame) {
        sites_.clear();
        crcOk_ = false;
        classified_ = false;
        if (!fi_.isHd) return;

        std::vector<std::uint16_t> fw(std::size_t(lineWords_) * fi_.totalLines);
        unpack10(frame, fw.size(), fw.data());

        // ANC is in the luma stream: the line starts with the EAV, whose first
        // word is chroma, so luma is the odd word of each pair.
        for (std::size_t k = 1; k + 40 < fw.size(); k += 2) {
            if (fw[k] != 0x000 || fw[k + 2] != 0x3FF || fw[k + 4] != 0x3FF) continue;
            if ((fw[k + 6] & 0xFF) != 0x60 || (fw[k + 8] & 0xFF) != 0x60) continue;
            const int dc = fw[k + 10] & 0xFF;
            if (dc < 16 || dc > 64) continue;
            AtcSite st;
            st.didWord = k + 6;
            st.udwWord = k + 12;
            st.dc      = dc;
            st.line    = int(k / std::size_t(lineWords_)) + 1;
            st.firstValue = readAtc(&fw[st.udwWord], fps_);
            sites_.push_back(st);
        }

        // Confirm where the line CRC lives before rewriting any. If the model
        // does not reproduce the untouched capture, leave CRCs alone rather
        // than corrupting lines that are currently valid.
        int checked = 0, matched = 0;
        for (const auto& st : sites_) {
            const std::size_t cov = std::size_t(st.line - 1) * lineWords_ +
                                    std::size_t(lineWords_ - activeWords_);
            const std::size_t at = std::size_t(st.line) * lineWords_ + 12;
            if (at + 4 >= fw.size()) continue;
            ++checked;
            bool both = true;
            for (int s = 0; s < 2; ++s) {
                const Crc18Words cw = crc18ToWords(
                    crc18Strided(&fw[cov + std::size_t(s)], crcWords_, 2));
                if (fw[at + s] != cw.crc0 || fw[at + 2 + s] != cw.crc1) both = false;
            }
            if (both) ++matched;
        }
        crcOk_ = checked > 0 && matched == checked;
    }

    // Decide which site carries the countdown, using a later frame: the one
    // whose timecode runs backwards is the countdown.
    void classify(const std::uint8_t* frame) {
        if (sites_.empty() || !fi_.isHd) { classified_ = true; return; }
        std::vector<std::uint16_t> fw(std::size_t(lineWords_) * fi_.totalLines);
        unpack10(frame, fw.size(), fw.data());
        for (auto& st : sites_)
            st.countdown = readAtc(&fw[st.udwWord], fps_) < st.firstValue;
        classified_ = true;
    }

    // Returns true if at least one site was patched.
    bool patch(std::uint8_t* frame, std::int64_t tod, std::int64_t left) {
        if (sites_.empty()) return false;
        int th, tm, ts, tf, ch, cm, cs, cf;
        framesToFields(tod,  fps_, th, tm, ts, tf);
        framesToFields(left, fps_, ch, cm, cs, cf);

        int hit = 0;
        for (const auto& st : sites_) {
            // Span the whole line block plus the next line's header: three of
            // the four ATC packets are in HANC, before the active samples, and
            // the CRC that covers the VANC one is in the following line.
            const std::size_t w0 = std::size_t(st.line - 1) * lineWords_;
            const std::size_t span = std::size_t(lineWords_) + 16;
            if (w0 % 4 || (w0 + span) / 4 * 5 > frameBytes_) continue;

            v_.resize(span);
            unpack10(frame + w0 / 4 * 5, span, v_.data());

            // Cheap confirmation that this site still holds an ATC packet. The
            // layout is stable within a stream, but a capture can splice.
            const std::size_t rel = st.didWord - w0;
            if (rel + 2 >= span) continue;
            if ((v_[rel] & 0xFF) != 0x60 || (v_[rel + 2] & 0xFF) != 0x60) continue;

            std::uint16_t* udw = &v_[st.udwWord - w0];
            std::uint16_t flat[16];
            for (int i = 0; i < 16; ++i) flat[i] = udw[std::size_t(i) * 2];
            if (st.countdown) writeAtc(flat, ch, cm, cs, cf);
            else              writeAtc(flat, th, tm, ts, tf);
            for (int i = 0; i < 16; ++i) udw[std::size_t(i) * 2] = flat[i];

            std::uint16_t pkt[3 + 64];
            const int words = 3 + st.dc;
            for (int i = 0; i < words; ++i) pkt[i] = v_[rel + std::size_t(i) * 2];
            v_[rel + std::size_t(words) * 2] = ancChecksum(pkt, std::size_t(words));

            if (crcOk_) {
                const std::size_t cov = std::size_t(lineWords_ - activeWords_);
                for (int s = 0; s < 2; ++s) {
                    const Crc18Words cw = crc18ToWords(
                        crc18Strided(&v_[cov + std::size_t(s)], crcWords_, 2));
                    v_[std::size_t(lineWords_) + 12 + std::size_t(s)] = cw.crc0;
                    v_[std::size_t(lineWords_) + 14 + std::size_t(s)] = cw.crc1;
                }
            }
            pack10(v_.data(), span, frame + w0 / 4 * 5);
            ++hit;
        }

        // The layout moved; relearn rather than silently stop rewriting.
        if (hit == 0 && ++missStreak_ >= 25) { missStreak_ = 0; discover(frame); }
        else if (hit) missStreak_ = 0;
        return hit > 0;
    }

private:
    SdiFormatInfo              fi_{};
    std::size_t                frameBytes_ = 0;
    int                        lineWords_ = 0, activeWords_ = 0, fps_ = 0;
    std::size_t                crcWords_ = 0;
    std::vector<AtcSite>       sites_;
    std::vector<std::uint16_t> v_;
    bool                       crcOk_ = false, classified_ = false;
    int                        missStreak_ = 0;
};

// xorshift64*: fast, good enough to decorrelate fault decisions, and seeded per
// run so two runs do not impair identically.
struct Rng {
    std::uint64_t s;
    explicit Rng(std::uint64_t seed) : s(seed ? seed : 0x9E3779B97F4A7C15ull) {}
    std::uint64_t next() {
        s ^= s >> 12; s ^= s << 25; s ^= s >> 27;
        return s * 0x2545F4914F6CDD1Dull;
    }
    bool chance(double p) {
        return p > 0.0 && double(next() >> 11) / 9007199254740992.0 < p;
    }
    std::uint32_t below(std::uint32_t n) { return n ? std::uint32_t(next() % n) : 0; }
};

}  // namespace

// ---------------------------------------------------------------------------

ReplayEngine::~ReplayEngine() { stop(); }

bool ReplayEngine::start(const ReplayConfig& cfg) {
    stop();
    {
        std::lock_guard<std::mutex> lk(mutex_);
        status_ = ReplayStatus{};
        config_ = cfg;
    }
    stopping_.store(false, std::memory_order_relaxed);
    running_.store(true, std::memory_order_relaxed);
    thread_ = std::thread(&ReplayEngine::run, this, cfg);
    return true;
}

void ReplayEngine::stop() {
    stopping_.store(true, std::memory_order_relaxed);
    if (thread_.joinable()) thread_.join();
    running_.store(false, std::memory_order_relaxed);
}

ReplayStatus ReplayEngine::status() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return status_;
}

ReplayConfig ReplayEngine::activeConfig() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return config_;
}

void ReplayEngine::run(ReplayConfig cfg) {
    auto fail = [&](const std::string& msg) {
        std::lock_guard<std::mutex> lk(mutex_);
        status_.running = false;
        status_.error = msg;
        running_.store(false, std::memory_order_relaxed);
    };

    // ---- source -------------------------------------------------------------
    PcapSource src;
    PcapSourceConfig sc;
    sc.fileRed       = cfg.fileRed;
    sc.fileBlue      = cfg.fileBlue;
    sc.ringFrames    = cfg.ringFrames;
    sc.skipTolerance = cfg.skipTolerance;
    if (!src.start(sc)) { fail(src.status().error); return; }

    const SdiFormatInfo& fi = src.formatInfo();
    const std::size_t frameBytes = src.frameBytes();
    const int fps = int(fi.frameRate() + 0.5);
    const std::uint64_t dgPerFrame =
        (std::uint64_t(frameBytes) + kHbrmtPayloadBytes - 1) / kHbrmtPayloadBytes;
    const double pps = double(dgPerFrame) * fi.frameRate();

    // Pre-roll. Parsing the first frame out of a multi-gigabyte capture takes
    // long enough that starting the pacer first would open with a burst of
    // starves and a backlog to claw back.
    bool repeated = false;
    std::uint8_t* frame =
        const_cast<std::uint8_t*>(src.next(15000, repeated));
    if (!frame) {
        const std::string e = src.status().error;
        src.stop();
        fail(e.empty() ? "no frames produced from the capture" : e);
        return;
    }

    AtcRewriter atc;
    const bool wantTc = cfg.rewriteTimecode && fi.isHd;
    if (wantTc) {
        atc.reset(fi, frameBytes);
        atc.discover(frame);
    }
    const bool rewriteTc = wantTc && atc.siteCount() > 0;

    // ---- sockets ------------------------------------------------------------
    MulticastSender txA, txB;
    if (!txA.open({cfg.pathA.group, cfg.pathA.port, cfg.pathA.interfaceIp},
                  cfg.ttl, cfg.loopback)) {
        const std::string e = "path A: " + txA.lastError();
        src.stop();
        fail(e);
        return;
    }
    txA.enableSegmentation(int(kDatagramBytes));
    const bool haveB = cfg.enablePathB;
    if (haveB) {
        if (!txB.open({cfg.pathB.group, cfg.pathB.port, cfg.pathB.interfaceIp},
                      cfg.ttl, cfg.loopback)) {
            const std::string e = "path B: " + txB.lastError();
            src.stop();
            fail(e);
            return;
        }
        txB.enableSegmentation(int(kDatagramBytes));
    }

    // ---- transmit -----------------------------------------------------------
    HbrmtHeader hb = hbrmtForFormat(fi);
    hb.r = std::uint8_t(cfg.ref);
    const double cfHz = hb.cf == 2 ? 148.5e6 : (hb.cf == 1 ? 148.5e6 / 1.001 : 0.0);
    const std::uint32_t videoTicks =
        cfHz > 0.0 ? std::uint32_t(cfHz / fi.frameRate() + 0.5) : 0;
    const std::uint32_t rtpStep = rtpTicksPerFrame(fi.frameRateNum, fi.frameRateDen);

    std::int64_t todBase = 0;
    {
        const std::time_t now = std::time(nullptr);
        std::tm lt{};
        localtime_s(&lt, &now);
        todBase = atcToFrames(lt.tm_hour, lt.tm_min, lt.tm_sec, 0, fps);
    }
    const std::int64_t framesPerDay = std::int64_t(86400) * fps;
    std::string todText, cdText;

    SpinPacer pacer;
    SpinPacer::elevateCurrentThread();
    pacer.start(pps);

    const int burstMax = MulticastSender::maxSegments(int(kDatagramBytes));
    std::vector<std::uint8_t> burst(std::size_t(burstMax) * kDatagramBytes);
    std::vector<int> order;
    order.reserve(std::size_t(burstMax) * 2);

    Rng rng(std::uint64_t(std::chrono::steady_clock::now().time_since_epoch().count()) ^
            0xA5A5F00DDEADBEEFull);
    const double p = cfg.faults.ratePercent / 100.0;
    int burstDropA = 0, burstDropB = 0;

    std::uint64_t streamPos = 0, sent = 0, repeats = 0;
    std::uint64_t droppedA = 0, droppedB = 0, reordered = 0, duplicated = 0, jumps = 0;
    std::uint16_t seq = 0;
    bool completed = false;

    {
        std::lock_guard<std::mutex> lk(mutex_);
        status_.running   = true;
        status_.formatText = formatDescription(fi.id);
        status_.targetPps  = pps;
        status_.atcPackets = atc.siteCount();
        status_.crcModelOk = atc.crcOk();
        status_.rewritingTimecode = rewriteTc;
    }

    // Emit one burst down one path, applying that path's impairments. Runs of
    // consecutive datagrams go out in a single syscall so the segmentation
    // offload still does the work; only the faults themselves cost extra calls.
    auto emit = [&](MulticastSender& tx, bool wantLoss, int& burstLeft,
                    std::uint64_t& dropped, int built) {
        order.clear();
        for (int k = 0; k < built; ++k) {
            if (burstLeft > 0) { --burstLeft; ++dropped; continue; }
            if (cfg.faults.burstLoss && rng.chance(p * 0.05)) {
                burstLeft = int(4 + rng.below(40));   // a glitch, not a blip
                --burstLeft; ++dropped;
                continue;
            }
            if (wantLoss && rng.chance(p)) { ++dropped; continue; }
            order.push_back(k);
            if (cfg.faults.duplicate && rng.chance(p)) { order.push_back(k); ++duplicated; }
        }
        if (cfg.faults.reorder && order.size() >= 2 && rng.chance(p * 4.0)) {
            const std::size_t i = rng.below(std::uint32_t(order.size() - 1));
            std::swap(order[i], order[i + 1]);
            ++reordered;
        }
        std::size_t i = 0;
        while (i < order.size()) {
            std::size_t j = i + 1;
            while (j < order.size() && order[j] == order[j - 1] + 1) ++j;
            tx.sendMany(burst.data() + std::size_t(order[i]) * kDatagramBytes,
                        int(kDatagramBytes), int(j - i));
            i = j;
        }
    };

    double lastPublish = 0.0;
    std::uint64_t lastSent = 0;

    while (!stopping_.load(std::memory_order_relaxed)) {
        int credit = 0;
        while (credit < burstMax) {
            const int got = pacer.acquire(burstMax - credit);
            if (got <= 0) break;
            credit += got;
        }
        if (credit <= 0) continue;

        int built = 0;
        for (; built < credit; ++built) {
            const std::uint64_t frameIndex = streamPos / dgPerFrame;
            const std::uint64_t idxInFrame = streamPos % dgPerFrame;

            if (idxInFrame == 0 && streamPos) {
                // Next frame. A miss returns the same one again rather than
                // stalling the wire; the counter makes that visible.
                std::uint8_t* nf = const_cast<std::uint8_t*>(src.next(0, repeated));
                if (nf) frame = nf;
                if (repeated) ++repeats;
            }
            if (idxInFrame == 0) {
                if (rewriteTc) {
                    if (!atc.classified() && frameIndex == 1) atc.classify(frame);
                    const std::int64_t tod =
                        (todBase + std::int64_t(frameIndex)) % framesPerDay;
                    const std::int64_t left = framesPerDay - tod;
                    todText = hmsf(tod, fps);
                    cdText  = hmsf(left, fps);
                    atc.patch(frame, tod, left);
                }
            }

            RtpHeader rtp;
            if (cfg.faults.seqJump && rng.chance(p * 0.02)) {
                seq = std::uint16_t(seq + 1 + rng.below(3000));
                ++jumps;
            }
            rtp.sequence  = seq++;
            rtp.timestamp = std::uint32_t(frameIndex * rtpStep);
            rtp.ssrc      = cfg.ssrc;
            rtp.marker    = (idxInFrame + 1 == dgPerFrame);

            hb.frCount = std::uint8_t(frameIndex);
            hb.videoTimestamp = std::uint32_t(frameIndex * videoTicks);

            // Frame-aligned with the tail zero-padded, as real broadcast kit
            // sends it. Every frame is independent, so the loop join is free.
            std::uint8_t chunk[kHbrmtPayloadBytes];
            const std::size_t within = std::size_t(idxInFrame) * kHbrmtPayloadBytes;
            const std::size_t take   = std::min(kHbrmtPayloadBytes, frameBytes - within);
            std::memcpy(chunk, frame + within, take);
            if (take < kHbrmtPayloadBytes)
                std::memset(chunk + take, 0, kHbrmtPayloadBytes - take);

            buildDatagram(rtp, hb, {chunk, kHbrmtPayloadBytes},
                          burst.data() + std::size_t(built) * kDatagramBytes,
                          kDatagramBytes);
            ++streamPos;
        }
        if (!built) continue;

        if (!cfg.faults.any()) {
            txA.sendMany(burst.data(), int(kDatagramBytes), built);
            if (haveB) txB.sendMany(burst.data(), int(kDatagramBytes), built);
        } else {
            emit(txA, cfg.faults.lossA, burstDropA, droppedA, built);
            if (haveB) emit(txB, cfg.faults.lossB, burstDropB, droppedB, built);
        }
        sent += std::uint64_t(built);

        const PacerStats ps = pacer.stats();
        if (cfg.maxSeconds > 0.0 && ps.elapsedSeconds >= cfg.maxSeconds) {
            completed = true;
            break;
        }
        if (ps.elapsedSeconds - lastPublish >= 0.25) {
            const double dt = ps.elapsedSeconds - lastPublish;
            const PcapSourceStatus ss = src.status();
            std::lock_guard<std::mutex> lk(mutex_);
            status_.frameIndex  = streamPos / dgPerFrame;
            status_.elapsedSeconds = ps.elapsedSeconds;
            status_.datagrams   = sent;
            status_.achievedPps = double(sent - lastSent) / dt;
            status_.wireMbps    = status_.achievedPps * double(kDatagramBytes + 28) * 8.0 / 1e6;
            status_.droppedA    = droppedA;
            status_.droppedB    = droppedB;
            status_.reordered   = reordered;
            status_.duplicated  = duplicated;
            status_.seqJumps    = jumps;
            status_.repeatedFrames = repeats;
            status_.tod         = todText;
            status_.countdown   = cdText;
            status_.source      = ss;
            status_.warning     = ss.warning;
            if (!ss.error.empty()) status_.error = ss.error;
            lastPublish = ps.elapsedSeconds;
            lastSent = sent;
        }
    }

    pacer.stop();
    src.releaseAll();
    src.stop();

    std::lock_guard<std::mutex> lk(mutex_);
    status_.running = false;
    status_.completed = completed;
    running_.store(false, std::memory_order_relaxed);
}

}  // namespace pcapreplay
