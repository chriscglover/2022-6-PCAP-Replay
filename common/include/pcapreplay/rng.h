// The one small random generator the replay uses.
//
// xorshift64* rather than <random>: the fault injector draws a few million
// times a second on the transmit thread, and std::mt19937 is 2.5 KB of state
// with a far heavier next(). Reproducibility across platforms matters more than
// statistical pedigree here -- the same seed must produce the same impairment
// pattern on Windows and Linux, which the standard distributions do not
// guarantee because their implementations differ.
#pragma once

#include <cstdint>

namespace pcapreplay {

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

    // Uniform in [lo, hi]. Used for skew targets and dwell times, not on the
    // per-datagram path.
    double uniform(double lo, double hi) {
        return lo + (hi - lo) * (double(next() >> 11) / 9007199254740992.0);
    }
};

}  // namespace pcapreplay
