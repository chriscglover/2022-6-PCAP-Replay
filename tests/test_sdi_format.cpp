// The format table is the thing everything else is derived from -- raster
// geometry, packet rate, the HBRMT code points a receiver reads to work out
// what it has been sent. A wrong row here is a stream that looks plausible and
// decodes to nothing.
#include "harness.h"

#include <set>

#include "pcapreplay/sdi_format.h"

using namespace pcapreplay;

TEST(sdi_format, every_row_is_self_consistent) {
    for (const SdiFormatInfo& fi : allFormats()) {
        if (fi.id == SdiFormat::Unknown) continue;
        const std::string where = fi.name;

        CHECK(fi.totalSamples > 0);
        CHECK(fi.totalLines > 0);
        CHECK(fi.frameRateNum > 0);
        CHECK(fi.frameRateDen > 0);

        // pack10 needs whole 4-word groups, and bytesPerFrame() claims to be a
        // whole number of bytes on the strength of it.
        CHECK((fi.totalSamples % 2) == 0);
        CHECK((fi.wordsPerFrame() % 4) == 0);
        CHECK((fi.wordsPerFrame() * 10 % 8) == 0);

        CHECK(fi.activeWidth > 0 && fi.activeWidth <= fi.totalSamples);
        CHECK(fi.activeHeight > 0 && fi.activeHeight <= fi.totalLines);

        // Active picture has to fit in the raster, per field.
        CHECK(fi.activeLinesPerField > 0);
        CHECK(fi.activeLinesPerField * fi.fieldsPerFrame() == fi.activeHeight);
        CHECK(fi.activeStartF1 >= 1);
        if (fi.interlacedOnWire()) {
            CHECK(fi.activeStartF2 >= 1);
            CHECK(fi.field1StartLine >= 1);
            CHECK(fi.field2StartLine >= 1);
        }
    }
}

TEST(sdi_format, hbrmt_codes_identify_a_format_uniquely) {
    // A receiver recovers the format from FRAME/FRATE/SAMPLE alone, so two rows
    // sharing all three would be indistinguishable on the wire.
    std::set<std::uint32_t> seen;
    for (const SdiFormatInfo& fi : allFormats()) {
        if (fi.id == SdiFormat::Unknown) continue;
        const std::uint32_t key = (std::uint32_t(fi.frameCode) << 16) |
                                  (std::uint32_t(fi.frateCode) << 8) |
                                  std::uint32_t(fi.sampleCode);
        // PsF shares its raster with the interlaced form and is separated by
        // FRAME, so it must still be distinct here.
        CHECK(seen.insert(key).second);

        CHECK_EQ(int(formatFromHbrmtCodes(fi.frameCode, fi.frateCode, fi.sampleCode)),
                 int(fi.id));
    }
}

TEST(sdi_format, unknown_codes_do_not_resolve) {
    CHECK_EQ(int(formatFromHbrmtCodes(0xFF, 0xFF, 0xFF)), int(SdiFormat::Unknown));
    // Right raster, impossible sampling.
    const SdiFormatInfo& fi = formatInfo(SdiFormat::HD1080i25);
    CHECK_EQ(int(formatFromHbrmtCodes(fi.frameCode, fi.frateCode, 0x0E)),
             int(SdiFormat::Unknown));
}

TEST(sdi_format, known_rasters_have_the_documented_size) {
    // 1080i25 is 2640 samples per line, not the 2200 of the 30 Hz variants:
    // the luma clock is 74.25 MHz for both, so the line has to be longer when
    // there are fewer frames. 2640 x 1125 x 25 = 74,250,000 exactly.
    //
    // The README quotes 7,425,000 bytes per frame; that number reaching the
    // wire is what makes the marker-bit frame cutting necessary.
    const SdiFormatInfo& hd = formatInfo(SdiFormat::HD1080i25);
    CHECK_EQ(hd.totalSamples, 2640);
    CHECK_EQ(hd.lumaClockHz, 74250000.0);
    CHECK_EQ(std::int64_t(hd.totalSamples) * hd.totalLines * hd.frameRateNum /
                 hd.frameRateDen,
             std::int64_t(74250000));
    CHECK_EQ(hd.totalLines, 1125);
    CHECK_EQ(hd.wordsPerFrame(), std::int64_t(5940000));
    CHECK_EQ(hd.bytesPerFrame(), std::int64_t(7425000));
    CHECK_EQ(hd.frameRateNum, 25);
    CHECK_EQ(hd.frameRateDen, 1);
    CHECK(hd.isHd);

    // 625i25 SD: 864x625, and no line-number or CRC words.
    const SdiFormatInfo& sd = formatInfo(SdiFormat::SD625i25);
    CHECK_EQ(sd.totalSamples, 864);
    CHECK_EQ(sd.totalLines, 625);
    CHECK(!sd.isHd);
}

TEST(sdi_format, the_thirty_hertz_rasters_are_the_short_ones) {
    // Same 74.25 MHz clock, more frames, so fewer samples per line.
    const SdiFormatInfo& fi = formatInfo(SdiFormat::HD1080i30);
    CHECK_EQ(fi.totalSamples, 2200);
    CHECK_EQ(fi.totalLines, 1125);
}

TEST(sdi_format, fractional_rates_are_exact_rationals) {
    // 29.97 must be 30000/1001, not a double. The RTP timestamp step is derived
    // from it and a receiver notices the difference.
    const SdiFormatInfo& fi = formatInfo(SdiFormat::HD1080i2997);
    CHECK_EQ(fi.frameRateNum, 30000);
    CHECK_EQ(fi.frameRateDen, 1001);
}

TEST(sdi_format, bit_rate_lands_where_the_standards_say) {
    // 1.485 Gb/s for HD, 270 Mb/s for SD, within rounding.
    const double hd = formatInfo(SdiFormat::HD1080i25).bitsPerSecond();
    CHECK(hd > 1.40e9 && hd < 1.50e9);
    const double sd = formatInfo(SdiFormat::SD625i25).bitsPerSecond();
    CHECK(sd > 2.6e8 && sd < 2.8e8);
    // 1080p50 is a 3 Gb/s format: twice the interlaced rate.
    const double p50 = formatInfo(SdiFormat::HD1080p50).bitsPerSecond();
    CHECK(p50 > 1.9 * hd && p50 < 2.1 * hd);
}

TEST(sdi_format, matching_a_raster_is_exact_not_approximate) {
    CHECK_EQ(int(matchFormat(1920, 1080, 25, 1, ScanMode::Interlaced)),
             int(SdiFormat::HD1080i25));
    CHECK_EQ(int(matchFormat(1280, 720, 50, 1, ScanMode::Progressive)),
             int(SdiFormat::HD720p50));
    // PsF is not the same thing as interlaced, even on the same raster.
    CHECK_EQ(int(matchFormat(1920, 1080, 25, 1, ScanMode::SegmentedFrame)),
             int(SdiFormat::HD1080psf25));
    // Nothing is scaled or rate-converted, so a near miss is Unknown.
    CHECK_EQ(int(matchFormat(1920, 1080, 24, 1, ScanMode::Progressive)),
             int(SdiFormat::Unknown));
    CHECK_EQ(int(matchFormat(3840, 2160, 50, 1, ScanMode::Progressive)),
             int(SdiFormat::Unknown));
}

TEST(sdi_format, line_flags_split_the_fields_correctly) {
    const SdiFormatInfo& fi = formatInfo(SdiFormat::HD1080i25);
    // 1080i25 field 1 starts at line 1, field 2 at 564.
    CHECK(!lineFlags(fi, fi.field1StartLine).f);
    CHECK(lineFlags(fi, fi.field2StartLine).f);
    // The first active line of each field carries picture, so V is clear.
    CHECK(!lineFlags(fi, fi.activeStartF1).v);
    CHECK(!lineFlags(fi, fi.activeStartF2).v);
    // Line 1 of 1080i25 is vertical blanking.
    CHECK(lineFlags(fi, 1).v);
}

TEST(sdi_format, active_rows_cover_the_picture_once) {
    for (SdiFormat f : {SdiFormat::HD1080i25, SdiFormat::HD720p50,
                        SdiFormat::SD625i25, SdiFormat::SD525i2997}) {
        const SdiFormatInfo& fi = formatInfo(f);
        std::set<int> rows;
        for (int line = 1; line <= fi.totalLines; ++line) {
            const int row = activeRowForLine(fi, line);
            if (row < 0) continue;
            CHECK(row < fi.activeHeight);
            CHECK(rows.insert(row).second);      // no line maps twice
        }
        // Every row of the picture is produced by exactly one raster line.
        CHECK_EQ(int(rows.size()), fi.activeHeight);
    }
}

TEST(sdi_format, a_description_exists_for_every_format) {
    for (const SdiFormatInfo& fi : allFormats()) {
        if (fi.id == SdiFormat::Unknown) continue;
        CHECK(!formatDescription(fi.id).empty());
    }
}
