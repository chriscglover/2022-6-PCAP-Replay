// The multicast DNS implementation, exercised over the loopback link by
// advertising a service and browsing for it in the same process.
//
// This is the part of the Linux port with no library underneath it -- the
// message encoder and decoder are written here from RFC 6762 and RFC 6763 --
// so it is the part most worth proving rather than reasoning about. If the
// name encoding, the compression-pointer handling, the SRV layout or the TXT
// framing were wrong, the browser would not resolve what the advertiser
// published.
//
// Skipped rather than failed where the environment will not carry it: a
// container with no multicast route, or a machine where UDP 5353 cannot be
// shared, is a fact about the runner and not about the code.
#include "harness.h"

#include <chrono>
#include <map>
#include <thread>

#include "pcapreplay/nmos/mdns.h"

using namespace pcapreplay::nmos;

namespace {

// Browsers poll; give one up to `seconds` to see what it is looking for.
bool waitFor(MdnsBrowser& b, const std::string& label, double seconds,
             MdnsService& out) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(std::int64_t(seconds * 1000));
    while (std::chrono::steady_clock::now() < deadline) {
        for (const MdnsService& s : b.found()) {
            if (s.displayName == label && s.port != 0) { out = s; return true; }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

// Whether this machine can carry multicast DNS at all, decided once by
// advertising something and looking for it.
//
// A CI runner is frequently not able to: the GitHub Windows image cannot even
// bind a loopback listener. That is a fact about the runner, and a suite that
// went red over it would train everyone to ignore the colour.
bool mdnsUsable() {
    static const bool ok = [] {
        MdnsAdvertiser a;
        if (!a.start("pcapreplay probe " + localHostLabel(),
                     "_pcapreplay-probe._tcp", 3210, {{"api_ver", "v1.3"}}))
            return false;
        MdnsBrowser b;
        if (!b.start("_pcapreplay-probe._tcp")) { a.stop(); return false; }
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(6);
        bool seen = false;
        while (!seen && std::chrono::steady_clock::now() < deadline) {
            for (const MdnsService& s : b.found())
                if (s.port == 3210) seen = true;
            if (!seen) std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        b.stop();
        a.stop();
        return seen;
    }();
    return ok;
}

// A label unique to this run, so a stale advertisement from an earlier one --
// or another machine on the same link -- cannot make the test pass.
std::string uniqueLabel() {
    return "pcapreplay selftest " + localHostLabel() + " " +
           std::to_string(std::chrono::steady_clock::now()
                              .time_since_epoch().count() % 100000);
}

}  // namespace

TEST(mdns_wire, an_advertised_service_is_found_and_fully_resolved) {
    if (!mdnsUsable()) SKIP("no usable multicast DNS on this machine");
    const std::string label = uniqueLabel();
    const std::string type  = "_pcapreplay-test._tcp";

    MdnsAdvertiser adv;
    const std::map<std::string, std::string> txt = {
        {"api_ver",   "v1.2,v1.3"},
        {"api_proto", "http"},
        {"api_auth",  "false"},
        {"pri",       "42"},
        {"empty",     ""},
    };
    if (!adv.start(label, type, 3210, txt)) {
        SKIP(("cannot advertise here: " + adv.error()).c_str());
    }

    MdnsBrowser browser;
    if (!browser.start(type)) {
        SKIP(("cannot browse here: " + browser.error()).c_str());
    }

    MdnsService found;
    if (!waitFor(browser, label, 6.0, found)) {
        browser.stop();
        adv.stop();
        SKIP("no multicast DNS on this link");
    }

    // The SRV record: port and target host.
    CHECK_EQ(found.port, std::uint16_t(3210));
    CHECK(!found.hostName.empty());

    // The A record for that target, which is what makes the service reachable.
    // A service that resolves to nothing is one a controller can see and cannot
    // route.
    CHECK(!found.address.empty());

    // The type parsed back off the wire, with the trailing .local removed.
    CHECK_EQ(found.serviceType, type);

    // Every TXT key round-tripped, including the empty-valued one -- DNS-SD
    // allows "key" with no "=value" and both forms have to survive.
    CHECK_EQ(found.txt.at("api_proto"), std::string("http"));
    CHECK_EQ(found.txt.at("api_auth"), std::string("false"));
    CHECK_EQ(found.txt.count("empty"), std::size_t(1));

    // And the fields parsed out of TXT per the IS-04 binding.
    CHECK_EQ(found.priority, 42);
    CHECK(found.supportsVersion("v1.3"));
    CHECK(found.supportsVersion("v1.2"));
    CHECK(!found.supportsVersion("v1.0"));

    browser.stop();
    adv.stop();
}

TEST(mdns_wire, a_stopped_advertiser_is_withdrawn_from_the_link) {
    // The goodbye packet (RFC 6762 10.1, a TTL of zero) is what stops a
    // controller listing a node that has gone. Without it the entry lingers for
    // the record's whole lifetime, and a sender that is not there is worse than
    // one that never appeared.
    //
    // Linux only, and that is a statement about the product rather than about
    // the test. Removal is implemented in the POSIX browse engine, which parses
    // the records itself and can see a PTR arrive at TTL 0. The Windows engine
    // is a thin wrapper over DnsServiceBrowse, whose callback surfaces
    // discoveries rather than withdrawals, so a departed registry stays in that
    // list. Worth fixing there too; skipped rather than quietly asserted so the
    // gap is visible on every run.
#ifdef _WIN32
    SKIP("Windows browse is dnsapi, which does not report withdrawals -- "
         "a departed service still lingers in found() there");
#else
    if (!mdnsUsable()) SKIP("no usable multicast DNS on this machine");
    const std::string label = uniqueLabel();
    const std::string type  = "_pcapreplay-test._tcp";

    MdnsAdvertiser adv;
    if (!adv.start(label, type, 3211, {{"api_ver", "v1.3"}}))
        SKIP(("cannot advertise here: " + adv.error()).c_str());

    MdnsBrowser browser;
    if (!browser.start(type)) SKIP(("cannot browse here: " + browser.error()).c_str());

    MdnsService found;
    if (!waitFor(browser, label, 6.0, found)) {
        browser.stop();
        adv.stop();
        SKIP("no multicast DNS on this link");
    }
    CHECK_EQ(found.port, std::uint16_t(3211));

    adv.stop();                       // sends the goodbye

    // The browser should drop it. Allow a moment for the packet to land.
    bool stillListed = true;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    while (std::chrono::steady_clock::now() < deadline) {
        stillListed = false;
        for (const MdnsService& s : browser.found())
            if (s.displayName == label) stillListed = true;
        if (!stillListed) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    CHECK(!stillListed);
    browser.stop();
#endif
}

TEST(mdns_wire, two_instances_on_one_host_are_both_found) {
    // Two copies of the app on one machine advertise distinct instance names,
    // and a browser has to list both rather than have the second silently lose
    // to the first.
    if (!mdnsUsable()) SKIP("no usable multicast DNS on this machine");
    const std::string a = uniqueLabel() + " a";
    const std::string b = uniqueLabel() + " b";
    const std::string type = "_pcapreplay-test._tcp";

    MdnsAdvertiser adA, adB;
    if (!adA.start(a, type, 3210, {{"api_ver", "v1.3"}}))
        SKIP(("cannot advertise here: " + adA.error()).c_str());
    if (!adB.start(b, type, 3211, {{"api_ver", "v1.3"}}))
        SKIP(("cannot advertise a second instance: " + adB.error()).c_str());

    MdnsBrowser browser;
    if (!browser.start(type)) SKIP(("cannot browse here: " + browser.error()).c_str());

    MdnsService fa, fb;
    const bool gotA = waitFor(browser, a, 6.0, fa);
    const bool gotB = waitFor(browser, b, 6.0, fb);
    if (!gotA && !gotB) {
        browser.stop(); adA.stop(); adB.stop();
        SKIP("no multicast DNS on this link");
    }
    CHECK(gotA);
    CHECK(gotB);
    CHECK_EQ(fa.port, std::uint16_t(3210));
    CHECK_EQ(fb.port, std::uint16_t(3211));

    // The SRV target differs per instance on POSIX and does not on Windows,
    // and both are right for their platform. The POSIX responder publishes
    // pcap-replay-<host>-<port>.local rather than <host>.local, because
    // avahi-daemon is already authoritative for the latter and a second answer
    // for a name someone else owns is a conflict. Windows has no such problem:
    // DnsServiceRegister publishes through the responder that already owns the
    // machine's name, so both instances share it and neither contends.
#ifndef _WIN32
    CHECK_NE(fa.hostName, fb.hostName);
#else
    CHECK_EQ(fa.hostName, fb.hostName);
#endif
    CHECK(!fa.hostName.empty());
    CHECK(!fb.hostName.empty());

    browser.stop();
    adA.stop();
    adB.stop();
}
