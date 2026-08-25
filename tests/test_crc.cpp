// The ST 292 line CRC has a fast table-driven form and a slow bitwise reference.
// The header says the reference is "kept as the reference the table is
// validated against" -- which was only true if something actually validated it.
#include "harness.h"

#include <random>
#include <vector>

#include "pcapreplay/crc.h"

using namespace pcapreplay;

TEST(crc, table_matches_the_bitwise_reference) {
    std::mt19937_64 rng(20226);
    for (std::size_t count : {1u, 2u, 7u, 64u, 1920u, 2200u}) {
        std::vector<std::uint16_t> words(count);
        for (auto& w : words) w = std::uint16_t(rng() & 0x3FFu);
        CHECK_EQ(crc18(words.data(), count), crc18Bitwise(words.data(), count));
    }
}

TEST(crc, continues_across_calls) {
    std::mt19937_64 rng(7);
    std::vector<std::uint16_t> words(100);
    for (auto& w : words) w = std::uint16_t(rng() & 0x3FFu);

    const std::uint32_t whole = crc18(words.data(), 100);
    const std::uint32_t part  = crc18(words.data(), 40);
    CHECK_EQ(crc18(words.data() + 40, 60, part), whole);
}

TEST(crc, strided_matches_a_gathered_copy) {
    // HD multiplexes Cb/Y/Cr/Y, so the luma CRC is a stride-2 walk rather than a
    // pass over a copy. The two must agree or every line reads as errored.
    std::mt19937_64 rng(99);
    std::vector<std::uint16_t> muxed(800);
    for (auto& w : muxed) w = std::uint16_t(rng() & 0x3FFu);

    std::vector<std::uint16_t> gathered;
    for (std::size_t i = 1; i < muxed.size(); i += 2) gathered.push_back(muxed[i]);

    CHECK_EQ(crc18Strided(muxed.data() + 1, gathered.size(), 2),
             crc18(gathered.data(), gathered.size()));
}

TEST(crc, stays_inside_eighteen_bits) {
    std::mt19937_64 rng(4242);
    for (int i = 0; i < 200; ++i) {
        std::uint16_t w[16];
        for (auto& x : w) x = std::uint16_t(rng() & 0x3FFu);
        CHECK_EQ(crc18(w, 16) & ~kCrc18Mask, 0u);
    }
}

TEST(crc, reflect18_is_its_own_inverse) {
    CHECK_EQ(reflect18(0), 0u);
    CHECK_EQ(reflect18(1), 1u << 17);
    CHECK_EQ(reflect18(reflect18(0x2AAAA)), 0x2AAAAu);
    CHECK_EQ(reflect18(kCrc18Mask), kCrc18Mask);
}

TEST(crc, carrier_words_round_trip) {
    // A CRC is split across two 10-bit words and read back by a receiver. If
    // this is not exact, a conformant receiver flags every line.
    std::mt19937_64 rng(11);
    for (int i = 0; i < 500; ++i) {
        const std::uint32_t crc = std::uint32_t(rng()) & kCrc18Mask;
        const Crc18Words w = crc18ToWords(crc);
        CHECK_EQ(crc18FromWords(w.crc0, w.crc1), crc);
        // Both carriers use the "bit 9 is the inverse of bit 8" convention.
        CHECK_EQ(std::uint16_t(w.crc0 >> 9), std::uint16_t(!((w.crc0 >> 8) & 1)));
        CHECK_EQ(std::uint16_t(w.crc1 >> 9), std::uint16_t(!((w.crc1 >> 8) & 1)));
    }
}

TEST(crc, with_not_b8_sets_the_inverse_bit) {
    CHECK_EQ(withNotB8(0x000), std::uint16_t(0x200));   // b8 clear -> b9 set
    CHECK_EQ(withNotB8(0x100), std::uint16_t(0x100));   // b8 set   -> b9 clear
    CHECK_EQ(withNotB8(0x0FF), std::uint16_t(0x2FF));
}

TEST(crc, anc_checksum_is_a_nine_bit_sum) {
    // ST 291: sum DID through the last user word, nine bits, with the not-b8
    // convention on top.
    const std::uint16_t pkt[] = {0x161, 0x101, 0x104, 0x001, 0x002, 0x003, 0x004};
    std::uint32_t sum = 0;
    for (std::uint16_t w : pkt) sum += w;
    CHECK_EQ(ancChecksum(pkt, sizeof pkt / sizeof pkt[0]),
             withNotB8(std::uint16_t(sum & 0x1FFu)));
}
