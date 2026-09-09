// The skew controller decides how fast a differential path delay may move.
// That rate is the whole safety property: a step change does not emulate a
// longer path, it gaps the lagging leg or releases a microburst, and a receiver
// would then be measuring the transient instead of the skew. So the cases that
// matter are the ones that pin the rate limit and the zero crossing.
#include "harness.h"

#include <cmath>

#include "pcapreplay/skew.h"

using namespace pcapreplay;

TEST(skew, disabled_by_default) {
    SkewSettings s;
    CHECK(!s.enabled());
    SkewController c;
    c.start(s, 1, 0.0);
    c.advance(10.0);
    CHECK_EQ(c.currentMs(), 0.0);
    CHECK_EQ(c.delayASec(), 0.0);
    CHECK_EQ(c.delayBSec(), 0.0);
}

TEST(skew, fixed_starts_at_its_value_rather_than_ramping_up) {
    // A fixed skew that ramped from zero would make every measurement depend on
    // knowing how long to wait first.
    SkewSettings s; s.fixedMs = 12.0;
    SkewController c; c.start(s, 1, 0.0);
    CHECK_EQ(c.currentMs(), 12.0);
    c.advance(5.0);
    CHECK_EQ(c.currentMs(), 12.0);
}

TEST(skew, positive_delays_b_negative_delays_a) {
    SkewSettings s; s.fixedMs = 8.0;
    SkewController c; c.start(s, 1, 0.0);
    CHECK_EQ(c.delayBSec(), 0.008);
    CHECK_EQ(c.delayASec(), 0.0);

    s.fixedMs = -8.0;
    c.start(s, 1, 0.0);
    CHECK_EQ(c.delayASec(), 0.008);
    CHECK_EQ(c.delayBSec(), 0.0);
}

TEST(skew, never_moves_faster_than_the_slew_rate) {
    // The one property the transmit ring depends on. 5 ms/s over 100 ms steps
    // must never advance more than 0.5 ms in a step, however far away the
    // target is.
    SkewSettings s;
    s.window = true; s.windowLoMs = -50.0; s.windowHiMs = 50.0;
    s.slewMsPerSec = 5.0; s.dwellMaxSec = 0.0;
    SkewController c; c.start(s, 99, 0.0);
    double prev = c.currentMs();
    for (int i = 1; i <= 400; ++i) {
        const double now = double(i) * 0.1;
        c.advance(now);
        CHECK(std::fabs(c.currentMs() - prev) <= 0.5 + 1e-9);
        prev = c.currentMs();
    }
}

TEST(skew, stays_inside_its_window) {
    SkewSettings s;
    s.window = true; s.windowLoMs = 4.0; s.windowHiMs = 9.0;
    s.slewMsPerSec = 50.0; s.dwellMaxSec = 0.1;
    SkewController c; c.start(s, 7, 0.0);
    for (int i = 1; i <= 2000; ++i) {
        c.advance(double(i) * 0.01);
        CHECK(c.currentMs() >= 4.0 - 1e-9);
        CHECK(c.currentMs() <= 9.0 + 1e-9);
    }
}

TEST(skew, a_window_straddling_zero_swaps_which_leg_leads) {
    SkewSettings s;
    s.window = true; s.windowLoMs = -20.0; s.windowHiMs = 20.0;
    s.slewMsPerSec = 200.0; s.dwellMaxSec = 0.0;
    SkewController c; c.start(s, 3, 0.0);
    bool sawA = false, sawB = false;
    for (int i = 1; i <= 4000; ++i) {
        c.advance(double(i) * 0.01);
        if (c.delayASec() > 0.0) sawA = true;
        if (c.delayBSec() > 0.0) sawB = true;
        // Only ever one leg held: the other is the reference.
        CHECK(!(c.delayASec() > 0.0 && c.delayBSec() > 0.0));
    }
    CHECK(sawA);
    CHECK(sawB);
}

TEST(skew, ring_depth_uses_the_absolute_worst_hold) {
    // A wholly negative window still needs the buffer -- it holds path A.
    SkewSettings s;
    s.window = true; s.windowLoMs = -30.0; s.windowHiMs = -10.0;
    CHECK_EQ(s.maxAbsMs(), 30.0);
    s.windowLoMs = -5.0; s.windowHiMs = 40.0;
    CHECK_EQ(s.maxAbsMs(), 40.0);
}

TEST(skew, refuses_what_it_cannot_honour) {
    SkewSettings s;
    CHECK(s.validate() == nullptr);
    s.fixedMs = 5000.0;
    CHECK(s.validate() != nullptr);          // beyond the ring cap
    s.fixedMs = 5.0; s.slewMsPerSec = 0.0;
    CHECK(s.validate() != nullptr);          // would never reach a target
    s.slewMsPerSec = 1.0; s.dwellMaxSec = -1.0;
    CHECK(s.validate() != nullptr);
}
