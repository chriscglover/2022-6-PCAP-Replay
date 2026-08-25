// The timing references and line numbers are what a receiver locks to. If the
// XYZ word or the line-number encoding is wrong the stream is not a stream, it
// is noise that happens to arrive at the right rate.
#include "harness.h"

#include "pcapreplay/crc.h"
#include "pcapreplay/sdi_raster.h"

using namespace pcapreplay;

TEST(sdi_raster, timing_xyz_has_the_documented_protection_bits) {
    // SMPTE ST 352 / ST 292 XYZ word: bit 9 always set, bit 8 = F, bit 7 = V,
    // bit 6 = H, then four protection bits and two zeros.
    const std::uint16_t sav = timingXyz(false, false, false);
    const std::uint16_t eav = timingXyz(false, false, true);
    CHECK(sav & 0x200);                       // bit 9 is always 1
    CHECK(eav & 0x200);
    CHECK_EQ(std::uint16_t((eav >> 6) & 1), std::uint16_t(1));   // H set for EAV
    CHECK_EQ(std::uint16_t((sav >> 6) & 1), std::uint16_t(0));

    CHECK_EQ(std::uint16_t((timingXyz(true, false, false) >> 8) & 1), std::uint16_t(1));
    CHECK_EQ(std::uint16_t((timingXyz(false, true, false) >> 7) & 1), std::uint16_t(1));

    // The low two bits are always zero.
    for (int f = 0; f < 2; ++f)
        for (int v = 0; v < 2; ++v)
            for (int h = 0; h < 2; ++h)
                CHECK_EQ(std::uint16_t(timingXyz(f, v, h) & 0x3), std::uint16_t(0));
}

TEST(sdi_raster, timing_xyz_protection_bits_are_self_consistent) {
    // The four protection bits are parity over F/V/H, which is what lets a
    // receiver reject a corrupted timing word rather than lock to it.
    for (int f = 0; f < 2; ++f) {
        for (int v = 0; v < 2; ++v) {
            for (int h = 0; h < 2; ++h) {
                const std::uint16_t w = timingXyz(f, v, h);
                const int F = (w >> 8) & 1, V = (w >> 7) & 1, H = (w >> 6) & 1;
                CHECK_EQ((w >> 5) & 1, V ^ H);        // P3
                CHECK_EQ((w >> 4) & 1, F ^ H);        // P2
                CHECK_EQ((w >> 3) & 1, F ^ V);        // P1
                CHECK_EQ((w >> 2) & 1, F ^ V ^ H);    // P0
            }
        }
    }
}

TEST(sdi_raster, line_numbers_round_trip_across_the_whole_raster) {
    for (int line = 1; line <= 1125; ++line) {
        std::uint16_t ln0 = 0, ln1 = 0;
        lineNumberToWords(line, ln0, ln1);
        CHECK_EQ(lineNumberFromWords(ln0, ln1), line);
        // Both carriers use the not-b8 convention.
        CHECK_EQ(std::uint16_t(ln0 >> 9), std::uint16_t(!((ln0 >> 8) & 1)));
        CHECK_EQ(std::uint16_t(ln1 >> 9), std::uint16_t(!((ln1 >> 8) & 1)));
    }
}

TEST(sdi_raster, hd_reserves_more_after_active_than_sd) {
    // HD (ST 292) carries EAV + line number + CRC; SD (ST 259) has EAV only.
    const SdiFormatInfo& hd = formatInfo(SdiFormat::HD1080i25);
    const SdiFormatInfo& sd = formatInfo(SdiFormat::SD625i25);
    CHECK(hd.isHd);
    CHECK(!sd.isHd);
    CHECK(postActiveWords(hd) > postActiveWords(sd));
    CHECK(savWords(hd) > 0);
    CHECK(savWords(sd) > 0);
}

TEST(sdi_raster, blanking_levels_are_the_legal_ones) {
    // 64 and 512 in 10-bit terms: the values a receiver expects in blanking,
    // and not 0, which is a reserved timing value.
    CHECK_EQ(kBlankLuma, std::uint16_t(64));
    CHECK_EQ(kBlankChroma, std::uint16_t(512));
    CHECK(kBlankLuma >= 4 && kBlankLuma <= 1019);
    CHECK(kBlankChroma >= 4 && kBlankChroma <= 1019);
}

TEST(sdi_raster, a_built_frame_is_the_size_the_table_promises) {
    // The pcap source rejects any frame whose length is not exactly this, so a
    // builder that disagreed with the table would reject every frame it made.
    for (SdiFormat f : {SdiFormat::HD1080i25, SdiFormat::HD720p50,
                        SdiFormat::SD625i25}) {
        SdiFrameBuilder b(f);
        CHECK_EQ(std::int64_t(b.finish().size()), formatInfo(f).bytesPerFrame());
    }
}

TEST(sdi_raster, a_built_frame_parses_back_to_the_picture_that_went_in) {
    // The end-to-end shape of the whole product in one test: a raster is built
    // with timing references, line numbers and CRCs, packed to the wire bytes
    // ST 2022-6 carries, and read back by the receiver-side parser that has to
    // find its own byte phase and line lock in the stream. If the EAV pattern,
    // the line-number encoding or the CRC coverage were wrong, the parser would
    // never lock -- which is precisely the failure mode a real receiver shows.
    for (SdiFormat f : {SdiFormat::HD1080i25, SdiFormat::HD720p50,
                        SdiFormat::SD625i25}) {
        const SdiFormatInfo& fi = formatInfo(f);

        // A picture with structure in it, so a shifted or dropped line shows up
        // rather than matching by luck.
        const int stride = fi.activeWidth * 2;
        std::vector<std::uint8_t> uyvy(std::size_t(stride) * fi.activeHeight);
        for (int y = 0; y < fi.activeHeight; ++y)
            for (int x = 0; x < stride; ++x)
                uyvy[std::size_t(y) * stride + x] =
                    std::uint8_t((x * 7 + y * 13) & 0xFF);

        SdiFrameBuilder builder(f);
        builder.writeActiveUyvy8(uyvy.data(), stride);
        const auto wire = builder.finish();

        SdiStreamParser parser;
        parser.reset(f);
        std::vector<SdiStreamParser::Frame> frames;
        // Fed twice: the parser has to find its phase and lock somewhere in the
        // first frame, so the second is the one that comes out whole.
        parser.feed(wire, frames);
        parser.feed(wire, frames);

        CHECK(parser.locked());
        CHECK(!frames.empty());
        if (frames.empty()) continue;

        const SdiStreamParser::Frame& fr = frames.back();
        CHECK_EQ(fr.width, fi.activeWidth);
        CHECK_EQ(fr.height, fi.activeHeight);
        CHECK_EQ(int(fr.format), int(f));
        // Every active line recovered, and no line whose CRC disagreed with
        // the one the builder computed.
        CHECK_EQ(fr.crcErrors, 0);
        CHECK_EQ(fr.linesRecovered, fi.activeHeight);

        // 8 -> 10 -> 8 is lossless, so the picture must come back identical.
        int differing = 0;
        for (int y = 0; y < fi.activeHeight; ++y)
            for (int x = 0; x < stride; ++x)
                if (fr.uyvy[std::size_t(y) * fr.strideBytes + x] !=
                    uyvy[std::size_t(y) * stride + x])
                    ++differing;
        CHECK_EQ(differing, 0);
    }
}
