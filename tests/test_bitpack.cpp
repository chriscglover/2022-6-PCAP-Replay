// The 10-bit packing is the hot loop of the whole transmitter and it has two
// implementations -- a scalar reference and an AVX2 path chosen at runtime.
// Both have to agree exactly, on every alignment, or the wire carries a raster
// that is subtly wrong in a way no counter will show.
#include "harness.h"

#include <random>
#include <vector>

#include "pcapreplay/bitpack.h"

using namespace pcapreplay;

namespace {

std::vector<std::uint16_t> randomWords(std::size_t n, std::uint64_t seed) {
    std::mt19937_64 rng(seed);
    std::vector<std::uint16_t> v(n);
    for (auto& w : v) w = std::uint16_t(rng() & 0x3FFu);
    return v;
}

}  // namespace

TEST(bitpack, pack_matches_the_documented_bit_layout) {
    // Straight from the header comment: four words become five bytes, MSB
    // first. Worked by hand so the test is independent of the implementation.
    const std::uint16_t src[4] = {0x3FF, 0x000, 0x2AA, 0x155};
    std::uint8_t dst[5] = {};
    scalar::pack10(src, 4, dst);

    CHECK_EQ(dst[0], std::uint8_t(0xFF));            // w0[9:2]
    CHECK_EQ(dst[1], std::uint8_t(0xC0));            // w0[1:0]<<6 | w1[9:4]
    CHECK_EQ(dst[2], std::uint8_t(0x0A));            // w1[3:0]<<4 | w2[9:6]
    CHECK_EQ(dst[3], std::uint8_t(0xA9));            // w2[5:0]<<2 | w3[9:8]
    CHECK_EQ(dst[4], std::uint8_t(0x55));            // w3[7:0]
}

TEST(bitpack, round_trip_preserves_every_word) {
    for (std::size_t count : {4u, 8u, 64u, 1024u, 3840u}) {
        const auto src = randomWords(count, count * 7919);
        std::vector<std::uint8_t> packed(packedBytes(count) + 8);
        std::vector<std::uint16_t> back(count);

        pack10(src.data(), count, packed.data());
        unpack10(packed.data(), count, back.data());
        for (std::size_t i = 0; i < count; ++i) CHECK_EQ(back[i], src[i]);
    }
}

TEST(bitpack, only_the_low_ten_bits_are_significant) {
    // Callers hand these words straight out of the raster, where the top six
    // bits are not guaranteed clear.
    const std::uint16_t dirty[4] = {0xFC00 | 0x123, 0xF000 | 0x2AA, 0x3FF, 0x0};
    const std::uint16_t clean[4] = {0x123, 0x2AA, 0x3FF, 0x0};
    std::uint8_t a[5] = {}, b[5] = {};
    scalar::pack10(dirty, 4, a);
    scalar::pack10(clean, 4, b);
    for (int i = 0; i < 5; ++i) CHECK_EQ(a[i], b[i]);
}

TEST(bitpack, avx2_pack_agrees_with_scalar) {
    if (!avx2Available()) SKIP("no AVX2 on this CPU; the scalar path is in use");

    // Every length in a range, not just round ones: the AVX2 packer uses
    // overlapping 8-byte stores for the bulk and an exact path for the final
    // group, so the boundary between them is where a mistake would live.
    for (std::size_t count = 4; count <= 512; count += 4) {
        const auto src = randomWords(count, count);
        std::vector<std::uint8_t> a(packedBytes(count) + 8, 0xCD);
        std::vector<std::uint8_t> b(packedBytes(count) + 8, 0xCD);
        scalar::pack10(src.data(), count, a.data());
        avx2::pack10(src.data(), count, b.data());
        for (std::size_t i = 0; i < packedBytes(count); ++i) CHECK_EQ(b[i], a[i]);
        // The overlapping stores must not run past what they were promised.
        for (std::size_t i = packedBytes(count); i < a.size(); ++i)
            CHECK_EQ(b[i], std::uint8_t(0xCD));
    }
}

TEST(bitpack, avx2_unpack_agrees_with_scalar) {
    if (!avx2Available()) SKIP("no AVX2 on this CPU; the scalar path is in use");

    for (std::size_t count = 4; count <= 512; count += 4) {
        const auto src = randomWords(count, count * 31);
        std::vector<std::uint8_t> packed(packedBytes(count) + 8);
        scalar::pack10(src.data(), count, packed.data());

        std::vector<std::uint16_t> a(count), b(count);
        scalar::unpack10(packed.data(), count, a.data());
        avx2::unpack10(packed.data(), count, b.data());
        for (std::size_t i = 0; i < count; ++i) CHECK_EQ(b[i], a[i]);
    }
}

TEST(bitpack, avx2_uyvy_widening_agrees_with_scalar) {
    if (!avx2Available()) SKIP("no AVX2 on this CPU; the scalar path is in use");

    for (std::size_t pixels : {2u, 16u, 64u, 720u, 1920u}) {
        std::vector<std::uint8_t> src(pixels * 2);
        std::mt19937_64 rng(pixels);
        for (auto& b : src) b = std::uint8_t(rng());

        std::vector<std::uint16_t> a(pixels * 2), b(pixels * 2);
        scalar::uyvy8ToWords(src.data(), pixels, a.data());
        avx2::uyvy8ToWords(src.data(), pixels, b.data());
        for (std::size_t i = 0; i < pixels * 2; ++i) CHECK_EQ(b[i], a[i]);

        std::vector<std::uint8_t> back1(pixels * 2), back2(pixels * 2);
        scalar::wordsToUyvy8(a.data(), pixels, back1.data());
        avx2::wordsToUyvy8(a.data(), pixels, back2.data());
        for (std::size_t i = 0; i < pixels * 2; ++i) {
            CHECK_EQ(back2[i], back1[i]);
            CHECK_EQ(back1[i], src[i]);          // 8 -> 10 -> 8 is lossless
        }
    }
}

TEST(bitpack, packed_bytes_is_five_per_four_words) {
    CHECK_EQ(packedBytes(4), std::size_t(5));
    CHECK_EQ(packedBytes(3840), std::size_t(4800));
    // A whole 1080i25 line: 2200 luma samples, 4400 muxed words.
    CHECK_EQ(packedBytes(4400), std::size_t(5500));
}
