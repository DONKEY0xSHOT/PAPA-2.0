#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/flirt/flirt.h"
#include "papa/features/extractors/papa_native/flirt/flirt_crc16.h"
#include "papa/features/extractors/papa_native/flirt/flirt_format.h"

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace flirt = papa::features::extractors::papa_native::flirt;

namespace {

void append_u8(std::vector<std::uint8_t>& buf, std::uint8_t v) {
    buf.push_back(v);
}

void append_u16_le(std::vector<std::uint8_t>& buf, std::uint16_t v) {
    buf.push_back(static_cast<std::uint8_t>(v & 0xFFU));
    buf.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFU));
}

void append_u32_le(std::vector<std::uint8_t>& buf, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) {
        buf.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFFU));
    }
}

void append_zeroes(std::vector<std::uint8_t>& buf, std::size_t n) {
    buf.insert(buf.end(), n, std::uint8_t{0});
}

// Big-endian u16, the on-disk encoding of the module CRC16
void append_u16_be(std::vector<std::uint8_t>& buf, std::uint16_t v) {
    buf.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFU));
    buf.push_back(static_cast<std::uint8_t>(v & 0xFFU));
}

// Offset of the little-endian features word inside every header
constexpr std::size_t kFeaturesOffset = 16;

// Clears the compression bit so the body that follows is read as plain
// uncompressed tree bytes
void clear_compression_bit(std::vector<std::uint8_t>& header) {
    header[kFeaturesOffset] = static_cast<std::uint8_t>(
        header[kFeaturesOffset] & ~0x10U);
}

// FLAIR vint16 encoder. Values below 0x80 fit in one byte. Larger values take two bytes
// with the lead byte's high bit set and the upper 7 value bits in the lead byte
void append_vle16(std::vector<std::uint8_t>& buf, std::uint16_t v) {
    if (v < 0x80U) {
        buf.push_back(static_cast<std::uint8_t>(v));
        return;
    }
    buf.push_back(static_cast<std::uint8_t>(0x80U | ((v >> 8) & 0x7FU)));
    buf.push_back(static_cast<std::uint8_t>(v & 0xFFU));
}

// One node child header with no wildcards: a vint16 length, an all-clear
// variant mask, then the literal pattern bytes in file order
void append_child_pattern(std::vector<std::uint8_t>& buf,
                          std::span<const std::uint8_t> pattern_bytes) {
    append_vle16(buf, static_cast<std::uint16_t>(pattern_bytes.size()));
    append_vle16(buf, 0);  // variant mask, no wildcard positions
    buf.insert(buf.end(), pattern_bytes.begin(), pattern_bytes.end());
}

// One module body inside a leaf, excluding the crc_len/crc16 pair. Emits a function
// size, one public name at relative offset zero, then a trailing parsing-flags byte
void append_module_body(std::vector<std::uint8_t>& buf,
                        std::uint32_t function_size,
                        std::string_view name,
                        std::uint8_t trailing_flags) {
    append_vle16(buf, static_cast<std::uint16_t>(function_size));
    append_vle16(buf, 0);  // relative offset of the name
    for (const char c : name) {
        buf.push_back(static_cast<std::uint8_t>(c));
    }
    append_u8(buf, trailing_flags);
}

// A minimal well-formed v10 FLIRT header. library_name is empty
std::vector<std::uint8_t> build_header_v10() {
    std::vector<std::uint8_t> buf;
    buf.reserve(64);
    static constexpr std::array<std::uint8_t, 6> kMagic = {'I', 'D', 'A', 'S', 'G', 'N'};
    buf.insert(buf.end(), kMagic.begin(), kMagic.end());  // 0..5
    append_u8     (buf, 10);           // 6   version
    append_u8     (buf, 0x01);         // 7   arch (x86)
    append_u32_le (buf, 0x00000002U);  // 8   file_types
    append_u16_le (buf, 0x0003U);      // 12  os_types
    append_u16_le (buf, 0x0004U);      // 14  app_types
    append_u16_le (buf, 0x0010U);      // 16  features (compressed=0x10)
    append_u16_le (buf, 0x0007U);      // 18  old_n_functions
    append_u16_le (buf, 0xABCDU);      // 20  pattern_crc16
    append_zeroes (buf, 12);           // 22..33  ctype
    append_u8     (buf, 0);            // 34  library_name_len
    append_u16_le (buf, 0x1234U);      // 35  ctypes_crc16
    append_u32_le (buf, 0x0000002AU);  // 37  n_functions (v9+)
    append_u16_le (buf, 0x0020U);      // 41  pattern_size = 32 (v10+)
    append_u16_le (buf, 0x0000U);      // 43  unknown (v10+)
    return buf;
}

// The three-byte pattern shared by the valid-sig and classify tests
constexpr std::array<std::uint8_t, 3> kPattern = {0x55, 0x8B, 0xEC};

// The tail bytes whose CRC16 the leaf module records
constexpr std::array<std::uint8_t, 5> kTail = {0xDE, 0xAD, 0xBE, 0xEF, 0x42};

// Builds a valid uncompressed .sig, a v10 header plus a body with one root child
// carrying kPattern and a single leaf module whose tail CRC16 covers kTail
std::vector<std::uint8_t> build_valid_sig() {
    std::vector<std::uint8_t> body;
    append_vle16(body, 1);                  // root child count
    append_child_pattern(body, kPattern);   // child 0 pattern
    append_vle16(body, 0);                   // child 0 is a leaf
    append_u8(body, static_cast<std::uint8_t>(kTail.size()));  // crc_len -> tail_length
    append_u16_be(body, flirt::flirt_crc16(kTail));            // crc16 -> tail_crc16
    append_module_body(body, 0x10, "foo", 0x00);

    auto sig = build_header_v10();
    clear_compression_bit(sig);
    sig.insert(sig.end(), body.begin(), body.end());
    return sig;
}

// Builds function bytes the matcher expects: a kMaxPatternLength pattern region
// (kPattern laid over a 0x90 fill) followed by `tail`
std::vector<std::uint8_t> make_function_bytes(std::span<const std::uint8_t> tail) {
    std::vector<std::uint8_t> buf(flirt::kMaxPatternLength + tail.size(), 0x90U);
    for (std::size_t i = 0; i < kPattern.size(); ++i) {
        buf[i] = kPattern[i];
    }
    for (std::size_t i = 0; i < tail.size(); ++i) {
        buf[flirt::kMaxPatternLength + i] = tail[i];
    }
    return buf;
}

}  // namespace

TEST_CASE("flirt_signature_set: default-constructed set has no trees") {
    const flirt::FlirtSignatureSet set;
    CHECK(set.tree_count() == 0U);
}

TEST_CASE("flirt_signature_set: add_from_buffer accepts a valid sig") {
    flirt::FlirtSignatureSet set;
    const auto sig = build_valid_sig();
    CHECK(set.add_from_buffer(sig));
    CHECK(set.tree_count() == 1U);
}

TEST_CASE("flirt_signature_set: add_from_buffer rejects garbage and leaves count unchanged") {
    flirt::FlirtSignatureSet set;
    const auto sig = build_valid_sig();
    REQUIRE(set.add_from_buffer(sig));
    REQUIRE(set.tree_count() == 1U);

    const std::array<std::uint8_t, 8> garbage{0x00, 0x01, 0x02, 0x03,
                                              0x04, 0x05, 0x06, 0x07};
    CHECK_FALSE(set.add_from_buffer(garbage));
    CHECK(set.tree_count() == 1U);  // unchanged, prior success retained
}

TEST_CASE("flirt_signature_set: classify matches the right tail and rejects a wrong one") {
    flirt::FlirtSignatureSet set;
    const auto sig = build_valid_sig();
    REQUIRE(set.add_from_buffer(sig));

    const auto good = make_function_bytes(kTail);
    CHECK(set.classify(good));

    // Same pattern, different tail bytes -> CRC mismatch -> no match
    constexpr std::array<std::uint8_t, 5> wrong_tail{0x01, 0x02, 0x03, 0x04, 0x05};
    const auto bad = make_function_bytes(wrong_tail);
    CHECK_FALSE(set.classify(bad));
}

TEST_CASE("flirt_signature_set: classify on an empty set never matches") {
    const flirt::FlirtSignatureSet set;
    const auto good = make_function_bytes(kTail);
    CHECK_FALSE(set.classify(good));
}

TEST_CASE("flirt_signature_set: embedded registry loads every bundled sig") {
#if defined(_WIN32) && defined(_MSC_VER)
    auto reg = flirt::embedded::registry();
    REQUIRE(reg.size() == 3U);
    for (const auto& e : reg) {
        CHECK(e.data != nullptr);
        CHECK(e.size > 100U);
    }
    auto set = flirt::FlirtSignatureSet::make_embedded();
    CHECK(set.tree_count() == reg.size());  // all 3 parse with zero drops
#else
    MESSAGE("FLIRT embedding is MSVC-only; registry is empty off MSVC");
    CHECK(flirt::embedded::registry().empty());
#endif
}
