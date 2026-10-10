#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/flirt/flirt.h"
#include "papa/features/extractors/papa_native/flirt/flirt_crc16.h"
#include "papa/features/extractors/papa_native/flirt/flirt_format.h"

#include "test_support.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace flirt = papa::features::extractors::papa_native::flirt;

namespace {

// The three-byte pattern shared by the valid-sig and classify tests
constexpr std::array<std::uint8_t, 3> kPattern = {0x55, 0x8B, 0xEC};

// The tail bytes whose CRC16 the leaf module records
constexpr std::array<std::uint8_t, 5> kTail = {0xDE, 0xAD, 0xBE, 0xEF, 0x42};

// Builds a valid uncompressed .sig, a v10 header plus a body with one root child
// carrying kPattern and a single leaf module whose tail CRC16 covers kTail
std::vector<std::uint8_t> build_valid_sig() {
    papa_tests::SigWriter body;
    body.vle16(1);                          // root child count
    body.child_pattern(kPattern);           // child 0 pattern
    body.vle16(0);                           // child 0 is a leaf
    body.u8(static_cast<std::uint8_t>(kTail.size()));  // crc_len -> tail_length
    body.u16_be(flirt::flirt_crc16(kTail));                    // crc16 -> tail_crc16
    body.module_body(0x10, "foo", 0x00);

    return papa_tests::sig_with_body(body.buf);
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

TEST_CASE("flirt_signature_set: add_from_buffer keeps each valid sig as a tree and drops garbage") {
    struct Add {
        std::vector<std::uint8_t> sig;
        bool                      accepted;
        std::size_t               trees;
    };
    struct Row {
        std::string_view label;
        std::vector<Add> adds;
    };
    const std::vector<std::uint8_t> garbage{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    const std::vector<Row> rows{
        {"a valid sig is accepted", {{build_valid_sig(), true, 1}}},
        {"garbage after a valid sig is rejected and leaves the count",
         {{build_valid_sig(), true, 1}, {garbage, false, 1}}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        flirt::FlirtSignatureSet set;
        for (std::size_t i = 0; i < row.adds.size(); ++i) {
            CAPTURE(i);
            CHECK(set.add_from_buffer(row.adds[i].sig) == row.adds[i].accepted);
            CHECK(set.tree_count() == row.adds[i].trees);
        }
    }
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

TEST_CASE("flirt_signature_set: an empty set has no trees and classifies nothing") {
    const flirt::FlirtSignatureSet set;
    CHECK(set.tree_count() == 0U);
    const auto good = make_function_bytes(kTail);
    CHECK_FALSE(set.classify(good));
}

TEST_CASE("flirt_signature_set: the embedded registry holds the vendored packs in order, byte for byte") {
    const std::filesystem::path dir = "third_party/flirt_sigs";
    REQUIRE_MESSAGE(std::filesystem::is_directory(dir),
                    "third_party/flirt_sigs not found, run the tests from the repository root");
    constexpr std::array<std::string_view, 3> kPacks = {
        "1_flare_msvc_rtf_32_64.sig", "2_flare_msvc_atlmfc_32_64.sig", "3_flare_common_libs.sig"};

    const auto reg = flirt::embedded::registry();
    REQUIRE(reg.size() == kPacks.size());
    for (std::size_t i = 0; i < kPacks.size(); ++i) {
        CAPTURE(kPacks[i]);
        CHECK(reg[i].path == kPacks[i]);
        for (const std::string_view chunk : reg[i].chunks) { CHECK(chunk.size() < 65535U); }
        const std::vector<std::uint8_t> joined = flirt::embedded::join(reg[i]);
        const std::string               file   = papa_tests::read_file(dir / kPacks[i]);
        CHECK(std::equal(joined.begin(), joined.end(), file.begin(), file.end(),
                         [](std::uint8_t a, char b) { return a == static_cast<std::uint8_t>(b); }));
    }
    CHECK(papa_tests::shared_flirt_sigs().tree_count() == kPacks.size());
}
