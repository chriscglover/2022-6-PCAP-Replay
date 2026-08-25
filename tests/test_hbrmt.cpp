// RTP and HBRMT headers are nibble-packed with several fields straddling byte
// boundaries, and the header comment says "this is all done by hand". Hand-done
// bit packing is exactly what a round-trip test is for.
#include "harness.h"

#include <vector>

#include "pcapreplay/hbrmt.h"

using namespace pcapreplay;

TEST(hbrmt, rtp_header_round_trips_every_field) {
    RtpHeader h;
    h.marker      = true;
    h.payloadType = 98;
    h.sequence    = 0xBEEF;
    h.timestamp   = 0x12345678;
    h.ssrc        = 0x20220006;

    std::uint8_t buf[kRtpHeaderBytes] = {};
    writeRtpHeader(h, buf);

    RtpHeader back;
    CHECK(readRtpHeader(buf, sizeof buf, back));
    CHECK_EQ(back.version, std::uint8_t(2));
    CHECK_EQ(back.marker, true);
    CHECK_EQ(back.payloadType, std::uint8_t(98));
    CHECK_EQ(back.sequence, std::uint16_t(0xBEEF));
    CHECK_EQ(back.timestamp, 0x12345678u);
    CHECK_EQ(back.ssrc, 0x20220006u);
}

TEST(hbrmt, rtp_marker_bit_does_not_bleed_into_the_payload_type) {
    // The marker is the top bit of the same byte as the payload type. Getting
    // that wrong gives a receiver payload type 226 and it drops the stream.
    RtpHeader h;
    h.payloadType = 98;
    h.marker = false;
    std::uint8_t a[kRtpHeaderBytes] = {};
    writeRtpHeader(h, a);
    CHECK_EQ(a[1], std::uint8_t(98));

    h.marker = true;
    std::uint8_t b[kRtpHeaderBytes] = {};
    writeRtpHeader(h, b);
    CHECK_EQ(b[1], std::uint8_t(98 | 0x80));
}

TEST(hbrmt, rtp_rejects_a_short_or_wrong_version_header) {
    std::uint8_t buf[kRtpHeaderBytes] = {};
    writeRtpHeader(RtpHeader{}, buf);
    RtpHeader out;
    CHECK(!readRtpHeader(buf, kRtpHeaderBytes - 1, out));

    buf[0] = 0x00;                       // version 0
    CHECK(!readRtpHeader(buf, sizeof buf, out));
}

TEST(hbrmt, header_round_trips_every_field) {
    HbrmtHeader h;
    h.ext        = 0;
    h.formatFlag = true;
    h.vsid       = 0;
    h.frCount    = 0xA5;
    h.r          = 3;
    h.s          = 0;
    h.fec        = 0;
    h.cf         = 2;
    h.map        = 0;
    h.frame      = 0x10;
    h.frate      = 0x14;
    h.sample     = 0x01;
    h.videoTimestamp = 0xDEADBEEF;

    std::vector<std::uint8_t> buf(h.sizeBytes());
    writeHbrmtHeader(h, buf.data());

    HbrmtHeader back;
    CHECK(readHbrmtHeader(buf.data(), buf.size(), back));
    CHECK_EQ(back.formatFlag, true);
    CHECK_EQ(back.vsid, std::uint8_t(0));
    CHECK_EQ(back.frCount, std::uint8_t(0xA5));
    CHECK_EQ(back.r, std::uint8_t(3));
    CHECK_EQ(back.cf, std::uint8_t(2));
    CHECK_EQ(back.frame, std::uint8_t(0x10));
    CHECK_EQ(back.frate, std::uint8_t(0x14));
    CHECK_EQ(back.sample, std::uint8_t(0x01));
    CHECK_EQ(back.videoTimestamp, 0xDEADBEEFu);
}

TEST(hbrmt, the_video_timestamp_is_present_only_when_cf_is_set) {
    HbrmtHeader h;
    h.cf = 0;
    CHECK_EQ(h.sizeBytes(), kHbrmtHeaderBytes);
    h.cf = 1;
    CHECK_EQ(h.sizeBytes(), kHbrmtHeaderBytes + kHbrmtTimestampBytes);
}

TEST(hbrmt, format_fields_come_from_the_table) {
    for (const SdiFormatInfo& fi : allFormats()) {
        if (fi.id == SdiFormat::Unknown) continue;
        const HbrmtHeader h = hbrmtForFormat(fi);
        CHECK_EQ(h.frame, fi.frameCode);
        CHECK_EQ(h.frate, fi.frateCode);
        CHECK_EQ(h.sample, fi.sampleCode);
        CHECK_EQ(h.cf, fi.cfCode);
        // A receiver only trusts FRAME/FRATE/SAMPLE when F says to.
        CHECK(h.formatFlag);
    }
}

TEST(hbrmt, a_whole_datagram_round_trips) {
    const SdiFormatInfo& fi = formatInfo(SdiFormat::HD1080i25);
    RtpHeader rtp;
    rtp.sequence = 1234;
    rtp.timestamp = 1080000;
    rtp.ssrc = 0x20220006;
    rtp.marker = true;
    HbrmtHeader hb = hbrmtForFormat(fi);
    hb.frCount = 7;

    std::vector<std::uint8_t> payload(kHbrmtPayloadBytes);
    for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = std::uint8_t(i * 31);

    std::vector<std::uint8_t> pkt(kDatagramBytes + 16);
    const std::size_t n = buildDatagram(rtp, hb, payload, pkt.data(), pkt.size());
    CHECK_EQ(n, kDatagramBytes);

    ParsedDatagram pd{};
    CHECK(parseDatagram({pkt.data(), n}, pd));
    CHECK_EQ(pd.rtp.sequence, std::uint16_t(1234));
    CHECK_EQ(pd.rtp.marker, true);
    CHECK_EQ(pd.hbrmt.frCount, std::uint8_t(7));
    CHECK_EQ(pd.hbrmt.frame, fi.frameCode);
    CHECK_EQ(pd.payload.size(), kHbrmtPayloadBytes);
    for (std::size_t i = 0; i < payload.size(); ++i)
        CHECK_EQ(pd.payload[i], payload[i]);
}

TEST(hbrmt, build_refuses_a_buffer_it_would_overrun) {
    std::vector<std::uint8_t> payload(kHbrmtPayloadBytes);
    std::vector<std::uint8_t> small(16);
    CHECK_EQ(buildDatagram(RtpHeader{}, HbrmtHeader{}, payload,
                           small.data(), small.size()), std::size_t(0));
}

TEST(hbrmt, parse_rejects_a_truncated_datagram) {
    ParsedDatagram pd{};
    std::vector<std::uint8_t> pkt(8, 0x80);
    CHECK(!parseDatagram({pkt.data(), pkt.size()}, pd));
}

TEST(hbrmt, the_datagram_is_the_documented_1400_bytes) {
    // 12 RTP + 8 HBRMT + 4 timestamp + 1376 payload. This is the number the
    // pacer's rate maths and the segmentation offload both assume.
    CHECK_EQ(kDatagramBytes, std::size_t(1400));
}

TEST(hbrmt, rtp_clock_steps_match_the_measured_stream) {
    // Measured from a real 1080i25 stream: exactly 27 MHz / 25 per frame.
    CHECK_EQ(rtpTicksPerFrame(25, 1), 1080000u);
    CHECK_EQ(rtpTicksPerFrame(50, 1), 540000u);
    CHECK_EQ(rtpTicksPerFrame(30000, 1001), 900900u);
    CHECK_EQ(rtpTicksPerFrame(60000, 1001), 450450u);
}
