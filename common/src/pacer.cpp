#include "pcapreplay/pacer.h"

#include <windows.h>
#include <mmsystem.h>

#include <algorithm>
#include <cmath>

namespace pcapreplay {
namespace {

inline std::int64_t qpc() {
    LARGE_INTEGER v;
    QueryPerformanceCounter(&v);
    return v.QuadPart;
}

inline double qpf() {
    LARGE_INTEGER v;
    QueryPerformanceFrequency(&v);
    return double(v.QuadPart);
}

// Below this, sleeping overshoots and we spin instead. 1.5 ms leaves room for
// a 1 ms timer granularity plus scheduling slop.
constexpr double kSpinThresholdSeconds = 0.0015;

// How much transmit debt the pacer will try to make up before re-anchoring.
//
// This exists to stop a stalled transmitter accruing unbounded debt (7.6
// million packets was observed once), after which the pacer returns maximum
// burst forever and stops pacing at all.
//
// 50 ms proved far too tight: ordinary scheduling jitter pushed the debt past
// it several times a second, and each clamp threw away schedule the thread had
// ample headroom to recover -- costing ~3% of the target rate and, with it,
// about a frame a second. 500 ms is still firmly bounded but lets normal
// hiccups be made up. Catch-up is inherently rate-limited because acquire()
// never returns more than one burst at a time.
constexpr double kMaxCatchUpSeconds = 0.500;

}  // namespace

SpinPacer::SpinPacer() : freq_(qpf()) {}

SpinPacer::~SpinPacer() { stop(); }

double SpinPacer::packetsPerSecondFor(std::int64_t bytesPerFrame,
                                      double frameRate,
                                      std::size_t payloadBytes) {
    if (payloadBytes == 0 || frameRate <= 0.0) return 0.0;
    const double perFrame =
        std::ceil(double(bytesPerFrame) / double(payloadBytes));
    return perFrame * frameRate;
}

void SpinPacer::start(double packetsPerSecond) {
    stop();
    pps_ = packetsPerSecond > 0.0 ? packetsPerSecond : 0.0;
    if (pps_ <= 0.0) return;

    // Tighten the OS timer so the coarse part of each wait is not 15 ms.
    timerRaised_ = timeBeginPeriod(1) == TIMERR_NOERROR;

    t0_ = qpc();
    issued_ = 0;
    slots_.store(0);
    sleeps_.store(0);
    spins_.store(0);
    maxBacklog_.store(0);
    maxLatenessUs_.store(0.0);
    resyncs_.store(0);
    running_ = true;
}

void SpinPacer::stop() {
    if (timerRaised_) {
        timeEndPeriod(1);
        timerRaised_ = false;
    }
    running_ = false;
}

void SpinPacer::resync() {
    t0_ = qpc();
    issued_ = 0;
}

int SpinPacer::acquire(int maxBurst) {
    if (!running_ || pps_ <= 0.0) return 0;
    if (maxBurst < 1) maxBurst = 1;

    for (;;) {
        const std::int64_t now = qpc();
        const double elapsed = double(now - t0_) / freq_;
        const std::int64_t due = std::int64_t(elapsed * pps_);
        std::int64_t credit = due - issued_;

        // Clamp the debt. If the transmitter stalls, `due` runs away from
        // `issued_` and the pacer would spend the rest of the session trying to
        // make up millions of packets -- returning maxBurst every time and
        // never actually pacing again. You cannot send a packet retroactively,
        // so past the catch-up limit we forgive the debt and resume pacing.
        // Observed backlog after the earlier stall: 7.6 million packets.
        const std::int64_t catchUpLimit = std::int64_t(pps_ * kMaxCatchUpSeconds) + 1;
        if (credit > catchUpLimit) {
            issued_ = due - catchUpLimit;
            credit = catchUpLimit;
            resyncs_.fetch_add(1, std::memory_order_relaxed);
        }

        if (credit >= 1) {
            // How late is the oldest packet in this slot against its ideal time?
            const double idealT = double(issued_) / pps_;
            const double lateUs = (elapsed - idealT) * 1e6;
            double prev = maxLatenessUs_.load(std::memory_order_relaxed);
            while (lateUs > prev &&
                   !maxLatenessUs_.compare_exchange_weak(prev, lateUs,
                                                         std::memory_order_relaxed)) {}

            std::int64_t prevBacklog = maxBacklog_.load(std::memory_order_relaxed);
            while (credit > prevBacklog &&
                   !maxBacklog_.compare_exchange_weak(prevBacklog, credit,
                                                      std::memory_order_relaxed)) {}

            if (credit > maxBurst) credit = maxBurst;
            issued_ += credit;
            slots_.fetch_add(1, std::memory_order_relaxed);
            return int(credit);
        }

        // Wait until the next packet is due. Absolute target, so a long sleep
        // that overshoots simply yields more credit next time round rather than
        // pushing the whole schedule late.
        const double nextIdeal = double(issued_ + 1) / pps_;
        const double waitS = nextIdeal - elapsed;

        if (waitS > kSpinThresholdSeconds) {
            sleeps_.fetch_add(1, std::memory_order_relaxed);
            const DWORD ms = DWORD((waitS - kSpinThresholdSeconds) * 1000.0);
            Sleep(ms ? ms : 1);
        } else {
            spins_.fetch_add(1, std::memory_order_relaxed);
            // Spin, but let a hyperthread sibling make progress.
            YieldProcessor();
        }
    }
}

bool SpinPacer::elevateCurrentThread() {
    return SetThreadPriority(GetCurrentThread(),
                             THREAD_PRIORITY_TIME_CRITICAL) != 0;
}

PacerStats SpinPacer::stats() const {
    PacerStats s;
    s.packetsIssued = issued_;
    s.slots      = slots_.load(std::memory_order_relaxed);
    s.sleeps     = sleeps_.load(std::memory_order_relaxed);
    s.spins      = spins_.load(std::memory_order_relaxed);
    s.maxBacklog = maxBacklog_.load(std::memory_order_relaxed);
    s.maxLatenessUs = maxLatenessUs_.load(std::memory_order_relaxed);
    s.resyncs    = resyncs_.load(std::memory_order_relaxed);
    s.targetPps  = pps_;
    if (running_ && freq_ > 0.0) {
        s.elapsedSeconds = double(qpc() - t0_) / freq_;
        if (s.elapsedSeconds > 0.0)
            s.achievedPps = double(issued_) / s.elapsedSeconds;
    }
    return s;
}

}  // namespace pcapreplay
