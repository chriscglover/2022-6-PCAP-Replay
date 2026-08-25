// NMOS resource IDs have to survive a restart, or every restart looks to the
// registry like a brand new node and every route a controller made points at
// something that no longer exists.
#include "harness.h"

#include <cctype>
#include <cstdlib>
#include <set>

#include "pcapreplay/nmos/uuid.h"

using namespace pcapreplay::nmos;

namespace {
bool looksLikeUuid(const std::string& s) {
    if (s.size() != 36) return false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (s[i] != '-') return false;
        } else if (!std::isxdigit(static_cast<unsigned char>(s[i]))) {
            return false;
        }
    }
    return true;
}
}  // namespace

TEST(uuid, v5_matches_the_rfc_4122_test_vector) {
    // The canonical example: the DNS namespace over "www.example.com".
    // If this passes, the SHA-1, the namespace byte order and the version and
    // variant bit stamping are all right.
    CHECK_EQ(uuidV5("6ba7b810-9dad-11d1-80b4-00c04fd430c8", "www.example.com"),
             std::string("2ed6657d-e927-568b-95e1-2665a8aea6a2"));
}

TEST(uuid, v5_is_deterministic_and_distinct_per_role) {
    const std::string a = resourceId("THEBEAST", "sender");
    CHECK_EQ(a, resourceId("THEBEAST", "sender"));       // same input, same id
    CHECK(looksLikeUuid(a));

    // Different role, different machine -- all must differ, or two resources
    // collide in the registry.
    std::set<std::string> ids;
    for (const char* host : {"THEBEAST", "EDIT-1", "docker2"})
        for (const char* role : {"node", "device", "source", "flow", "sender"})
            CHECK(ids.insert(resourceId(host, role)).second);
    CHECK_EQ(ids.size(), std::size_t(15));
}

TEST(uuid, v5_stamps_version_and_variant) {
    const std::string id = resourceId("host", "sender");
    CHECK_EQ(id[14], '5');                               // version 5
    // Variant: the first nibble of octet 8 is 8, 9, a or b.
    const char v = id[19];
    CHECK(v == '8' || v == '9' || v == 'a' || v == 'b');
}

TEST(uuid, v4_is_well_formed_and_not_repeated) {
    std::set<std::string> seen;
    for (int i = 0; i < 200; ++i) {
        const std::string id = uuidV4();
        CHECK(looksLikeUuid(id));
        CHECK_EQ(id[14], '4');
        const char v = id[19];
        CHECK(v == '8' || v == '9' || v == 'a' || v == 'b');
        CHECK(seen.insert(id).second);
    }
}

TEST(uuid, the_app_namespace_is_a_valid_uuid) {
    CHECK(looksLikeUuid(kPcapReplayNamespace));
}

TEST(uuid, tai_version_is_ordered_and_well_formed) {
    // The registry orders resource updates by this string, so it must parse as
    // "<seconds>:<nanoseconds>" and must not go backwards.
    const std::string a = taiVersion();
    const std::size_t colon = a.find(':');
    CHECK(colon != std::string::npos);
    const long long secs  = std::atoll(a.substr(0, colon).c_str());
    const long long nanos = std::atoll(a.substr(colon + 1).c_str());
    CHECK(secs > 1700000000LL);              // comfortably after 2023
    CHECK(nanos >= 0 && nanos < 1000000000LL);

    const std::string b = taiVersion();
    const long long bs = std::atoll(b.substr(0, b.find(':')).c_str());
    CHECK(bs >= secs);
}

TEST(uuid, an_invalid_namespace_yields_nothing_rather_than_rubbish) {
    CHECK(uuidV5("not-a-uuid", "x").empty());
    CHECK(uuidV5("", "x").empty());
}
