// The DNS-SD record interpretation shared by both platforms' browse engines.
// Getting api_ver parsing wrong is how a registry that is plainly on the
// network gets rejected as unusable.
#include "harness.h"

#include "mdns_internal.h"
#include "pcapreplay/nmos/mdns.h"

using namespace pcapreplay::nmos;

TEST(mdns, both_registration_types_are_browsed) {
    // IS-04 named the Registration API _nmos-registration._tcp up to v1.2 and
    // added the shorter _nmos-register._tcp at v1.3, because the first breaks
    // the 16-character limit in RFC 6763 7.2. Browsing one alone means a
    // registry that is plainly present is never seen.
    const auto types = registryServiceTypes();
    CHECK_EQ(types.size(), std::size_t(2));
    bool shortName = false, longName = false;
    for (const auto& t : types) {
        if (t == "_nmos-register._tcp")     shortName = true;
        if (t == "_nmos-registration._tcp") longName = true;
    }
    CHECK(shortName);
    CHECK(longName);
}

TEST(mdns, service_types_are_qualified_into_the_local_domain) {
    CHECK_EQ(detail::qualify("_nmos-register._tcp"),
             std::string("_nmos-register._tcp.local"));
    // Already qualified must not be doubled.
    CHECK_EQ(detail::qualify("_nmos-node._tcp.local"),
             std::string("_nmos-node._tcp.local"));
}

TEST(mdns, csv_splitting_tolerates_what_real_kit_emits) {
    CHECK_EQ(detail::splitCsv("v1.2,v1.3").size(), std::size_t(2));
    // Spaces are not allowed by the binding but real kit emits them anyway.
    const auto v = detail::splitCsv(" v1.0, v1.1 ,v1.2 ");
    CHECK_EQ(v.size(), std::size_t(3));
    CHECK_EQ(v[0], std::string("v1.0"));
    CHECK_EQ(v[2], std::string("v1.2"));
    CHECK(detail::splitCsv("").empty());
    CHECK_EQ(detail::splitCsv("v1.3").size(), std::size_t(1));
}

TEST(mdns, names_are_split_into_label_and_type) {
    MdnsService s;
    s.instance = "nmos-cpp_registration_10-10-101-201:80._nmos-register._tcp.local";
    detail::deriveNames(s);
    CHECK_EQ(s.displayName,
             std::string("nmos-cpp_registration_10-10-101-201:80"));
    // The trailing .local comes off; which type it answered on is kept, since
    // that is the quickest way to tell an old registry from a v1.3 one.
    CHECK_EQ(s.serviceType, std::string("_nmos-register._tcp"));
}

TEST(mdns, txt_records_populate_the_parsed_fields) {
    MdnsService s;
    s.txt = {{"pri", "99"}, {"api_proto", "https"},
             {"api_auth", "true"}, {"api_ver", "v1.0,v1.1,v1.2,v1.3"}};
    detail::applyTxtRecords(s);
    CHECK_EQ(s.priority, 99);
    CHECK_EQ(s.apiProto, std::string("https"));
    CHECK_EQ(s.apiAuth, std::string("true"));
    CHECK_EQ(s.apiVersions.size(), std::size_t(4));
    CHECK(s.supportsVersion("v1.3"));
    CHECK(!s.supportsVersion("v1.4"));
}

TEST(mdns, defaults_hold_when_a_registry_advertises_nothing) {
    MdnsService s;
    detail::applyTxtRecords(s);
    CHECK_EQ(s.priority, 100);
    CHECK_EQ(s.apiProto, std::string("http"));
    // IS-04 says an absent api_ver means v1.0 only, but several registries
    // publish nothing and serve current versions happily -- so an empty list is
    // "try it" rather than "refuse it".
    CHECK(s.supportsVersion("v1.3"));
}

TEST(mdns, the_base_url_prefers_a_resolved_address) {
    MdnsService s;
    s.hostName = "nmos-registry.local";
    s.port = 80;
    detail::applyTxtRecords(s);
    // Without an A record all we have is a .local name, which needs an mDNS
    // resolver in the C library to be useful.
    CHECK_EQ(s.baseUrl("v1.3"),
             std::string("http://nmos-registry.local:80/x-nmos/registration/v1.3"));

    s.address = "10.10.101.201";
    CHECK_EQ(s.baseUrl("v1.3"),
             std::string("http://10.10.101.201:80/x-nmos/registration/v1.3"));
}

TEST(mdns, the_browser_picks_the_lowest_priority_that_serves_the_version) {
    // "Lowest wins" is the DNS-SD convention and the opposite of intuition.
    MdnsBrowser b;
    MdnsService pick;
    CHECK(!b.best("v1.3", pick));            // nothing found yet
    CHECK(b.found().empty());
    // rejection() is empty when nothing was discovered at all, as opposed to
    // "found something unusable", which is a different message.
    CHECK(b.rejection("v1.3").empty());
}

TEST(mdns, the_local_host_label_is_a_single_label) {
    const std::string h = localHostLabel();
    CHECK(!h.empty());
    // A machine with a search domain reports "host.example.com" from
    // gethostname; the NMOS seed and the DNS-SD instance name want the short
    // form, and a dot in a DNS-SD instance label is its own kind of trouble.
    CHECK(h.find('.') == std::string::npos);
}
