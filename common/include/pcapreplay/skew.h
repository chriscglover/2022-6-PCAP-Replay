// ST 2022-7 differential path delay -- one leg deliberately behind the other.
//
// Why this exists: a -7 receiver has to absorb the delay difference between its
// two paths, and that is the one property a same-host replay cannot produce by
// accident. Both legs leave one pacer in the same slot, so without this the
// differential is always zero and the receiver's window is never exercised.
//
// Two rules shape the whole design.
//
// **A path can only be made later, never earlier.** So the signed differential
// is applied as a delay on whichever leg is behind: skew > 0 delays B, skew < 0
// delays A, and both delays are max(0, +/-skew). Crossing zero is therefore
// continuous -- B's delay falls to nothing, then A's rises from nothing -- and
// no common baseline delay is needed to swap which leg leads.
//
// **Skew must never step.** Increasing it by X instantly means the lagging leg
// sends nothing at all for X; decreasing it releases X worth of buffered
// packets at once, which at 3G is a 1,350-packet microburst. Either way the
// receiver would be measuring the transient rather than the skew. So a target
// is approached at a bounded rate: while skew moves at r ms per second the
// lagging leg runs r/1000 slower (or faster) than the source, so the default
// 1 ms/s is a 0.1% rate deviation -- indistinguishable from a slowly
// lengthening path, which is exactly what it is emulating.
//
// The window mode wanders randomly rather than sweeping periodically, for the
// same reason the impairments do: a periodic pattern can line up with a
// receiver's own buffering and either flatter or unfairly punish it.
#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>

#include "pcapreplay/rng.h"

namespace pcapreplay {

struct SkewSettings {
    // Fixed differential in milliseconds, signed: >0 delays path B, <0 delays
    // path A. Ignored when `window` is set.
    double fixedMs = 0.0;

    // Wander randomly within [windowLoMs, windowHiMs] instead. Either bound may
    // be negative, so a window that straddles zero swaps which leg leads as it
    // runs.
    bool   window = false;
    double windowLoMs = 0.0;
    double windowHiMs = 0.0;

    // Maximum rate of change, milliseconds of skew per second of real time.
    double slewMsPerSec = 1.0;

    // On reaching a target, hold it for a random interval up to this long
    // before choosing the next one, so the stream also spends time at a steady
    // differential rather than moving constantly.
    double dwellMaxSec = 2.0;

    bool enabled() const { return window || fixedMs != 0.0; }

    double loMs() const { return window ? std::min(windowLoMs, windowHiMs) : fixedMs; }
    double hiMs() const { return window ? std::max(windowLoMs, windowHiMs) : fixedMs; }

    // The deepest either leg is ever held. This sizes the transmit ring, so it
    // is the absolute value: a window of -30..-10 still needs 30 ms of buffer.
    double maxAbsMs() const {
        return std::max(std::fabs(loMs()), std::fabs(hiMs()));
    }

    // Empty means valid. Checked before the sockets open so a bad request is
    // refused at startup rather than silently reduced -- an under-sized window
    // that quietly clamps would report a skew it is not applying.
    const char* validate() const {
        if (slewMsPerSec <= 0.0 || slewMsPerSec > 1000.0)
            return "skew slew rate must be greater than 0 and at most 1000 ms/s";
        if (dwellMaxSec < 0.0 || dwellMaxSec > 3600.0)
            return "skew dwell must be between 0 and 3600 s";
        if (maxAbsMs() > 1000.0)
            return "skew must be within +/-1000 ms";
        return nullptr;
    }
};

// Holds the current differential and moves it toward a target at the configured
// rate. No clock of its own: the caller passes monotonic seconds, which keeps it
// testable without waiting for real time to pass.
class SkewController {
public:
    void start(const SkewSettings& s, std::uint64_t seed, double nowSec) {
        set_ = s;
        rng_ = Rng(seed);
        last_ = nowSec;
        if (!s.enabled()) { current_ = target_ = 0.0; return; }
        // Open at the target rather than ramping up from zero: the point of a
        // fixed skew is to be at that skew, and a run that spends its first
        // seconds elsewhere would need the caller to know how long to wait.
        current_ = target_ = s.window ? rng_.uniform(s.loMs(), s.hiMs()) : s.fixedMs;
        dwellUntil_ = nowSec;
    }

    void advance(double nowSec) {
        const double dt = nowSec - last_;
        last_ = nowSec;
        if (!set_.enabled() || dt <= 0.0) return;

        if (current_ != target_) {
            const double step = set_.slewMsPerSec * dt;
            if (std::fabs(target_ - current_) <= step) {
                current_ = target_;
                dwellUntil_ = nowSec + rng_.uniform(0.0, set_.dwellMaxSec);
            } else {
                current_ += std::copysign(step, target_ - current_);
            }
            return;
        }
        if (set_.window && nowSec >= dwellUntil_)
            target_ = rng_.uniform(set_.loMs(), set_.hiMs());
    }

    double currentMs() const { return current_; }
    double targetMs()  const { return target_; }

    // Delay applied to each leg, seconds. Exactly one is non-zero away from the
    // zero crossing; both are zero when the differential is zero.
    double delayASec() const { return current_ < 0.0 ? -current_ / 1000.0 : 0.0; }
    double delayBSec() const { return current_ > 0.0 ?  current_ / 1000.0 : 0.0; }

private:
    SkewSettings  set_;
    Rng           rng_{1};
    double        current_ = 0.0;
    double        target_ = 0.0;
    double        last_ = 0.0;
    double        dwellUntil_ = 0.0;
};

}  // namespace pcapreplay
