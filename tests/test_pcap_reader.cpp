// The link-layer dissector decides whether a capture is readable at all. A
// capture taken with `tcpdump -i any` is Linux cooked, one from a tap is
// Ethernet, one from a BSD box may be raw IP -- and an Ethernet-only reader
// silently rejects every packet of the other kinds rather than saying so.
#include "harness.h"

#include <vector>

#include "pcapreplay/pcap_reader.h"

using namespace pcapreplay;

namespace {

// An IPv4 + UDP datagram with `payload`, prefixed by `link` bytes of whatever
// link layer is being exercised.
std::vector<std::uint8_t> makePacket(const std::vector<std::uint8_t>& link,
                                     const std::vector<std::uint8_t>& payload,
                                     std::uint16_t srcPort = 5004,
                                     std::uint16_t dstPort = 40000,
                                     int ihlWords = 5) {
    std::vector<std::uint8_t> p = link;
    const std::size_t udpLen = 8 + payload.size();
    const std::size_t ipLen  = std::size_t(ihlWords) * 4 + udpLen;

    p.push_back(std::uint8_t(0x40 | ihlWords));      // version 4, IHL
    p.push_back(0);
    p.push_back(std::uint8_t(ipLen >> 8));
    p.push_back(std::uint8_t(ipLen));
    p.insert(p.end(), {0, 0, 0, 0, 8});
    p.push_back(17);                                  // UDP
    p.insert(p.end(), {0, 0});
    p.insert(p.end(), {10, 0, 0, 1});                 // src 10.0.0.1
    p.insert(p.end(), {239, 1, 2, 3});                // dst 239.1.2.3
    for (int i = 5; i < ihlWords; ++i)                // IP options
        p.insert(p.end(), {0, 0, 0, 0});

    p.push_back(std::uint8_t(srcPort >> 8)); p.push_back(std::uint8_t(srcPort));
    p.push_back(std::uint8_t(dstPort >> 8)); p.push_back(std::uint8_t(dstPort));
    p.push_back(std::uint8_t(udpLen >> 8));  p.push_back(std::uint8_t(udpLen));
    p.insert(p.end(), {0, 0});                        // checksum
    p.insert(p.end(), payload.begin(), payload.end());
    return p;
}

const std::vector<std::uint8_t> kEthernet = {
    0x01, 0x00, 0x5e, 0x01, 0x02, 0x03,   // dst MAC
    0x02, 0x00, 0x00, 0x00, 0x00, 0x01,   // src MAC
    0x08, 0x00,                            // ethertype IPv4
};

}  // namespace

TEST(pcap_reader, ethernet_is_dissected) {
    const std::vector<std::uint8_t> payload{1, 2, 3, 4, 5};
    const auto pkt = makePacket(kEthernet, payload);
    UdpView u;
    CHECK(parseUdp(pkt.data(), pkt.size(), u, 1));
    CHECK_EQ(u.dstPort, std::uint16_t(40000));
    CHECK_EQ(u.srcPort, std::uint16_t(5004));
    CHECK_EQ(u.len, payload.size());
    CHECK_EQ(ipStr(u.dstIp), std::string("239.1.2.3"));
    CHECK_EQ(ipStr(u.srcIp), std::string("10.0.0.1"));
    for (std::size_t i = 0; i < payload.size(); ++i) CHECK_EQ(u.payload[i], payload[i]);
}

TEST(pcap_reader, vlan_tags_are_walked_through) {
    // Broadcast networks tag media VLANs as a matter of course; a reader that
    // stops at the first ethertype sees none of it.
    std::vector<std::uint8_t> link = {
        0x01, 0x00, 0x5e, 0x01, 0x02, 0x03,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x81, 0x00, 0x00, 0x64,            // 802.1Q, VLAN 100
        0x08, 0x00,
    };
    const auto pkt = makePacket(link, {9, 9, 9});
    UdpView u;
    CHECK(parseUdp(pkt.data(), pkt.size(), u, 1));
    CHECK_EQ(u.dstPort, std::uint16_t(40000));
    CHECK_EQ(u.len, std::size_t(3));
}

TEST(pcap_reader, qinq_double_tags_are_walked_through) {
    std::vector<std::uint8_t> link = {
        0x01, 0x00, 0x5e, 0x01, 0x02, 0x03,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x88, 0xa8, 0x00, 0x64,            // 802.1ad outer
        0x81, 0x00, 0x00, 0xc8,            // 802.1Q inner
        0x08, 0x00,
    };
    const auto pkt = makePacket(link, {7});
    UdpView u;
    CHECK(parseUdp(pkt.data(), pkt.size(), u, 1));
    CHECK_EQ(u.len, std::size_t(1));
}

TEST(pcap_reader, the_other_link_types_are_dissected) {
    struct { std::uint32_t linktype; std::size_t headerBytes; const char* what; } kinds[] = {
        {101, 0,  "RAW IPv4"},
        {12,  0,  "RAW_IP (BSD)"},
        {228, 0,  "IPV4"},
        {113, 16, "Linux SLL -- what `tcpdump -i any` produces"},
        {276, 20, "Linux SLL2"},
        {0,   4,  "NULL / loopback"},
    };
    for (const auto& k : kinds) {
        const std::vector<std::uint8_t> link(k.headerBytes, 0);
        const auto pkt = makePacket(link, {4, 5, 6, 7});
        UdpView u;
        CHECK(parseUdp(pkt.data(), pkt.size(), u, k.linktype));
        CHECK_EQ(u.dstPort, std::uint16_t(40000));
        CHECK_EQ(u.len, std::size_t(4));
    }
}

TEST(pcap_reader, ip_options_are_skipped_using_ihl) {
    // A fixed 20-byte assumption reads the UDP header out of the options.
    const auto pkt = makePacket(kEthernet, {1, 2, 3, 4}, 5004, 40000, /*ihl*/ 7);
    UdpView u;
    CHECK(parseUdp(pkt.data(), pkt.size(), u, 1));
    CHECK_EQ(u.dstPort, std::uint16_t(40000));
    CHECK_EQ(u.len, std::size_t(4));
}

TEST(pcap_reader, non_udp_and_non_ipv4_are_rejected) {
    UdpView u;

    auto pkt = makePacket(kEthernet, {1, 2, 3});
    pkt[kEthernet.size() + 9] = 6;                    // TCP, not UDP
    CHECK(!parseUdp(pkt.data(), pkt.size(), u, 1));

    std::vector<std::uint8_t> arp = kEthernet;
    arp[12] = 0x08; arp[13] = 0x06;                   // ARP
    arp.resize(60, 0);
    CHECK(!parseUdp(arp.data(), arp.size(), u, 1));

    // Raw link types sanity-check the version nibble instead of an ethertype.
    std::vector<std::uint8_t> notIpv4(40, 0x60);      // looks like IPv6
    CHECK(!parseUdp(notIpv4.data(), notIpv4.size(), u, 101));
}

TEST(pcap_reader, truncated_packets_are_rejected_rather_than_read_past) {
    const auto pkt = makePacket(kEthernet, {1, 2, 3, 4, 5, 6, 7, 8});
    UdpView u;
    // Every truncation length must be refused, not just the obvious ones.
    for (std::size_t n = 0; n < pkt.size() - 8; ++n)
        CHECK(!parseUdp(pkt.data(), n, u, 1));
}

TEST(pcap_reader, a_snaplen_truncated_payload_is_clamped_to_what_is_there) {
    // `tcpdump` without -s 0 records a short payload but leaves the UDP length
    // field describing the whole datagram. Trusting the header would read past
    // the buffer.
    auto pkt = makePacket(kEthernet, std::vector<std::uint8_t>(200, 0xAB));
    pkt.resize(pkt.size() - 100);          // as if the snaplen cut it short
    UdpView u;
    CHECK(parseUdp(pkt.data(), pkt.size(), u, 1));
    CHECK_EQ(u.len, std::size_t(100));
    CHECK(u.payload + u.len <= pkt.data() + pkt.size());
}

TEST(pcap_reader, unknown_link_types_are_refused_not_guessed) {
    UdpView u;
    const auto pkt = makePacket(kEthernet, {1, 2, 3});
    CHECK(!parseUdp(pkt.data(), pkt.size(), u, 9999));
    CHECK_EQ(linkHeaderBytes(9999), -2);
    CHECK_EQ(linkHeaderBytes(1), -1);          // Ethernet: variable
    CHECK_EQ(linkHeaderBytes(113), 16);
}

TEST(pcap_reader, ip_text_formats_correctly) {
    CHECK_EQ(ipStr(0), std::string("0.0.0.0"));
    CHECK_EQ(ipStr(0xFFFFFFFFu), std::string("255.255.255.255"));
    CHECK_EQ(ipStr(0xEF010203u), std::string("239.1.2.3"));
}
