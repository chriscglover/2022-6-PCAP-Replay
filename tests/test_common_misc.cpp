// The smaller pieces: settings persistence, address validation, pacing maths
// and the status panel.
#include "harness.h"

#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <string>

#include "pcapreplay/hbrmt.h"

#include "pcapreplay/net_interfaces.h"
#include "pcapreplay/pacer.h"
#include "pcapreplay/settings.h"
#include "pcapreplay/status_text.h"

using namespace pcapreplay;

// ---- multicast address validation -----------------------------------------

TEST(net, multicast_groups_are_validated_against_the_usable_range) {
    CHECK(isValidMulticastGroup("239.1.1.1"));
    CHECK(isValidMulticastGroup("224.0.1.1"));
    CHECK(isValidMulticastGroup("239.255.255.255"));

    // Not multicast at all.
    CHECK(!isValidMulticastGroup("10.0.0.1"));
    CHECK(!isValidMulticastGroup("192.168.1.1"));
    CHECK(!isValidMulticastGroup("240.0.0.1"));
    CHECK(!isValidMulticastGroup("0.0.0.0"));

    // The link-local control block 224.0.0.0/24, which routers never forward.
    // Sending media there looks fine on the bench and vanishes at the first hop.
    CHECK(!isValidMulticastGroup("224.0.0.1"));
    CHECK(!isValidMulticastGroup("224.0.0.251"));   // mDNS itself

    // Not addresses.
    CHECK(!isValidMulticastGroup(""));
    CHECK(!isValidMulticastGroup("239.1.1"));
    CHECK(!isValidMulticastGroup("239.1.1.256"));
    CHECK(!isValidMulticastGroup("not an address"));
}

TEST(net, ipv4_parsing_yields_network_byte_order) {
    std::uint32_t be = 0;
    CHECK(parseIpv4("1.2.3.4", be));
    const std::uint8_t* b = reinterpret_cast<const std::uint8_t*>(&be);
    CHECK_EQ(b[0], std::uint8_t(1));
    CHECK_EQ(b[3], std::uint8_t(4));
    CHECK(!parseIpv4("1.2.3", be));
    CHECK(!parseIpv4("", be));
}

TEST(net, enumeration_returns_something_usable_and_ordered) {
    const auto ifaces = enumerateInterfaces(true);
    CHECK(!ifaces.empty());

    // Loopback is always offered, so a sender and receiver on one machine is
    // always possible -- and it sorts last so it is never the default.
    bool haveLoopback = false;
    for (const auto& ni : ifaces) if (ni.loopback) haveLoopback = true;
    CHECK(haveLoopback);

    // Physical before virtual among the interfaces that are up. A docker bridge
    // reporting 10 Gb/s must not outrank a real NIC, or multicast leaves by the
    // wrong link and fails silently.
    bool seenVirtual = false;
    for (const auto& ni : ifaces) {
        if (!ni.up || ni.loopback) continue;
        if (ni.virtualAdapter) seenVirtual = true;
        else CHECK(!seenVirtual);
    }

    for (const auto& ni : ifaces) CHECK(!ni.displayName().empty());
}

TEST(net, an_interface_can_be_found_by_its_own_address) {
    for (const auto& ni : enumerateInterfaces(true)) {
        if (ni.ipv4.empty()) continue;
        NetInterface found;
        CHECK(findInterfaceByIp(ni.ipv4, found));
        CHECK_EQ(found.ipv4, ni.ipv4);
        break;
    }
    NetInterface none;
    CHECK(!findInterfaceByIp("203.0.113.99", none));
    CHECK(!findInterfaceByName("no-such-nic-here", none));
}

// ---- pacing ----------------------------------------------------------------

TEST(pacer, packet_rate_matches_the_documented_figures) {
    // 1080i25 is 134,925 packets/sec -- the number the README quotes and the
    // one the live runs actually achieve.
    const SdiFormatInfo& hd = formatInfo(SdiFormat::HD1080i25);
    const double pps = SpinPacer::packetsPerSecondFor(hd.bytesPerFrame(),
                                                      hd.frameRate(),
                                                      kHbrmtPayloadBytes);
    CHECK_EQ(std::int64_t(pps + 0.5), std::int64_t(134925));

    // 1080p50 is twice that.
    const SdiFormatInfo& p50 = formatInfo(SdiFormat::HD1080p50);
    const double pps50 = SpinPacer::packetsPerSecondFor(p50.bytesPerFrame(),
                                                        p50.frameRate(),
                                                        kHbrmtPayloadBytes);
    CHECK_EQ(std::int64_t(pps50 + 0.5), std::int64_t(269850));
}

TEST(pacer, degenerate_inputs_do_not_divide_by_zero) {
    CHECK_EQ(SpinPacer::packetsPerSecondFor(1000, 25.0, 0), 0.0);
    CHECK_EQ(SpinPacer::packetsPerSecondFor(1000, 0.0, 1376), 0.0);
}

TEST(pacer, a_short_run_lands_close_to_the_target_rate) {
    // Not a precision claim -- CI runners are shared and preemptible. This
    // catches a pacer that does not pace at all, which is the failure that
    // matters: bursting a frame at line rate then idling looks perfect on a
    // throughput graph and destroys a real receiver.
    SpinPacer p;
    p.start(10000.0);                       // 10 kHz, cheap to run
    CHECK(p.running());
    const auto t0 = std::chrono::steady_clock::now();
    std::int64_t issued = 0;
    while (std::chrono::duration<double>(std::chrono::steady_clock::now() - t0)
               .count() < 0.30)
        issued += p.acquire(8);
    const double elapsed =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    p.stop();

    const double achieved = double(issued) / elapsed;
    // Generous bounds: the point is that it is pacing, not free-running.
    CHECK(achieved > 5000.0);
    CHECK(achieved < 20000.0);
    CHECK(p.stats().targetPps == 10000.0);
}

// ---- settings --------------------------------------------------------------

TEST(settings, values_survive_a_round_trip_through_the_file) {
    // The defect this covers is not hypothetical: the dialog only ever saved on
    // Start, so a capture browsed to and then routed over IS-05 was forgotten,
    // and the NMOS labels registered with no format in them.
    const std::string name = "pcapreplay-selftest";
    Settings w(name);
    if (!w.usable()) SKIP("no writable config directory in this environment");

    w.setString("red", "/srv/captures/red.pcap");
    w.setInt("a_port", 40000);
    w.setBool("seven", true);
    w.setBool("nmos", false);
    w.setString("nmos_label", "PCAP Replay");

    Settings r(name);
    CHECK_EQ(r.getString("red", ""), std::string("/srv/captures/red.pcap"));
    CHECK_EQ(r.getInt("a_port", 0), 40000);
    CHECK_EQ(r.getBool("seven", false), true);
    CHECK_EQ(r.getBool("nmos", true), false);
    CHECK_EQ(r.getString("nmos_label", ""), std::string("PCAP Replay"));

    // Absent keys fall back rather than reading as zero -- a port of 0 means
    // "ephemeral" here, so getting one by accident is not harmless.
    CHECK_EQ(r.getInt("never_written", 3210), 3210);
    CHECK_EQ(r.getString("never_written", "fallback"), std::string("fallback"));

    // Overwriting updates in place rather than appending a second key.
    w.setString("red", "/srv/captures/other.pcap");
    CHECK_EQ(Settings(name).getString("red", ""),
             std::string("/srv/captures/other.pcap"));

    std::remove(w.path().c_str());
}

TEST(settings, paths_with_spaces_and_unicode_survive) {
    const std::string name = "pcapreplay-selftest-paths";
    Settings w(name);
    if (!w.usable()) SKIP("no writable config directory in this environment");
    const std::string path = "/srv/off air/caf\xc3\xa9 \xe2\x80\x94 red.pcap";
    w.setString("red", path);
    CHECK_EQ(Settings(name).getString("red", ""), path);
    std::remove(w.path().c_str());
}

// ---- status panel ----------------------------------------------------------

TEST(status_text, an_idle_engine_says_so_rather_than_printing_zeroes) {
    ReplayStatus s;
    CHECK_EQ(statusText(s, "\n"), std::string("Idle"));

    s.completed = true;
    CHECK(statusText(s, "\n").find("Finished") != std::string::npos);

    s.completed = false;
    s.error = "cannot open red.pcap";
    CHECK(statusText(s, "\n").find("cannot open red.pcap") != std::string::npos);
}

TEST(status_text, a_running_engine_reports_the_fields_that_matter) {
    ReplayStatus s;
    s.running = true;
    s.formatText = "1080i25 (1080i50)";
    s.destinationA = "239.1.1.1:40000";
    s.frameIndex = 1234567;
    s.targetPps = 134925;
    s.achievedPps = 134925;
    s.source.merging = true;

    const std::string t = statusText(s, "\n");
    CHECK(t.find("1080i25") != std::string::npos);
    CHECK(t.find("239.1.1.1:40000") != std::string::npos);
    CHECK(t.find("ST 2022-7, both legs") != std::string::npos);
    // Big counts get thousands separators, or a ten-digit number is unreadable.
    CHECK(t.find("1,234,567") != std::string::npos);
    // A single leg says so rather than leaving path B blank.
    CHECK(t.find("single leg, ST 2022-6") != std::string::npos);

    // The line endings are the caller's choice: a Win32 edit control will not
    // render a bare newline.
    CHECK(statusText(s, "\r\n").find("\r\n") != std::string::npos);
    CHECK(t.find('\r') == std::string::npos);
}

TEST(status_text, commas_group_from_the_right) {
    CHECK_EQ(commas(0), std::string("0"));
    CHECK_EQ(commas(999), std::string("999"));
    CHECK_EQ(commas(1000), std::string("1,000"));
    CHECK_EQ(commas(1234567890ull), std::string("1,234,567,890"));
}
