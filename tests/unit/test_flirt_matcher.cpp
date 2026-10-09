#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/flirt/flirt_crc16.h"
#include "papa/features/extractors/papa_native/flirt/flirt_format.h"
#include "papa/features/extractors/papa_native/flirt/flirt_matcher.h"
#include "papa/features/extractors/papa_native/flirt/flirt_tree.h"

#include "test_support.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace flirt = papa::features::extractors::papa_native::flirt;

namespace {

// Builds a function-bytes buffer: a 32-byte pattern region followed by a tail. The
// pattern region is filled with `fill`, then `prefix` is laid over its start
std::vector<std::uint8_t> make_function_bytes(std::span<const std::uint8_t> prefix,
                                              std::span<const std::uint8_t> tail,
                                              std::uint8_t fill = 0x90U) {
    std::vector<std::uint8_t> buf(flirt::kMaxPatternLength + tail.size(), fill);
    for (std::size_t i = 0; i < prefix.size() && i < flirt::kMaxPatternLength; ++i) {
        buf[i] = prefix[i];
    }
    for (std::size_t i = 0; i < tail.size(); ++i) {
        buf[flirt::kMaxPatternLength + i] = tail[i];
    }
    return buf;
}

flirt::FlirtTree make_tree(std::unique_ptr<flirt::FlirtNode> root) {
    flirt::FlirtHeader hdr;
    hdr.version = 10;
    return flirt::FlirtTree{hdr, std::move(root)};
}

}  // namespace

TEST_CASE("flirt_matcher: match_flirt needs a tree, the whole pattern region and tail, and the tail's CRC") {
    constexpr std::array<std::uint8_t, 3> kPrefix{0x55, 0x8B, 0xEC};
    constexpr std::array<std::uint8_t, 5> kTail{0xDE, 0xAD, 0xBE, 0xEF, 0x42};
    constexpr std::array<std::uint8_t, 8> kLongTail{0x01, 0x02, 0x03, 0x04,
                                                    0x05, 0x06, 0x07, 0x08};
    // A one-node tree on kPrefix whose module records tail_crc over tail_length bytes
    const auto leaf_tree = [](std::uint16_t tail_crc, std::size_t tail_length) {
        auto root = std::make_unique<flirt::FlirtNode>();
        root->pattern = papa_tests::pattern({0x55, 0x8B, 0xEC});
        root->leaf_modules.push_back({tail_crc, static_cast<std::uint16_t>(tail_length)});
        return make_tree(std::move(root));
    };
    const flirt::FlirtTree empty;
    auto one_byte_root = std::make_unique<flirt::FlirtNode>();
    one_byte_root->pattern = papa_tests::pattern({0x55});
    one_byte_root->leaf_modules.push_back({0x0000U, 0U});
    const flirt::FlirtTree one_byte  = make_tree(std::move(one_byte_root));
    const flirt::FlirtTree right_crc = leaf_tree(flirt::flirt_crc16(kTail), kTail.size());
    const flirt::FlirtTree wrong_crc =
        leaf_tree(static_cast<std::uint16_t>(flirt::flirt_crc16(kTail) ^ 0x1U), kTail.size());
    const flirt::FlirtTree long_tail = leaf_tree(flirt::flirt_crc16(kLongTail), kLongTail.size());

    const auto full = make_function_bytes(kPrefix, kLongTail);
    // Exactly kMaxPatternLength bytes, with no tail bytes at all
    std::vector<std::uint8_t> just_pattern(flirt::kMaxPatternLength, 0x90U);
    std::copy(kPrefix.begin(), kPrefix.end(), just_pattern.begin());

    struct Row {
        std::string_view          label;
        const flirt::FlirtTree*   tree;
        std::vector<std::uint8_t> buf;
        bool                      matches;
    };
    const std::vector<Row> rows{
        {"a null tree against some bytes", &empty, {0x01, 0x02, 0x03, 0x04}, false},
        {"a null tree against no bytes", &empty, {}, false},
        {"an empty buffer against a real tree", &one_byte, {}, false},
        {"a single leaf with a matching pattern and the right tail CRC", &right_crc,
         make_function_bytes(kPrefix, kTail), true},
        {"a matching pattern with a wrong tail CRC", &wrong_crc,
         make_function_bytes(kPrefix, kTail), false},
        // The full buffer establishes that the CRC and pattern are correct
        {"the full pattern region and tail", &long_tail, full, true},
        {"one byte short of the pattern region plus tail", &long_tail,
         {full.begin(), full.end() - 1}, false},
        {"the pattern region alone cannot cover an 8-byte tail CRC window", &long_tail,
         just_pattern, false},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        CHECK(flirt::match_flirt(*row.tree, row.buf) == row.matches);
    }
}

TEST_CASE("flirt_matcher: non-matching pattern prunes subtree but sibling still matches") {
    constexpr std::array<std::uint8_t, 4> tail{0x11, 0x22, 0x33, 0x44};
    const std::uint16_t crc = flirt::flirt_crc16(tail);
    const auto len = static_cast<std::uint16_t>(tail.size());

    // Root matches anything (empty pattern). Two children share the root: the
    // first demands a prefix the buffer lacks, the second matches it
    auto root = std::make_unique<flirt::FlirtNode>();

    auto wrong_child = std::make_unique<flirt::FlirtNode>();
    wrong_child->pattern = papa_tests::pattern({0xCC, 0xCC, 0xCC});
    wrong_child->leaf_modules.push_back({crc, len});  // right CRC, wrong pattern
    root->children.push_back(std::move(wrong_child));

    auto right_child = std::make_unique<flirt::FlirtNode>();
    right_child->pattern = papa_tests::pattern({0x48, 0x89, 0x5C});
    right_child->leaf_modules.push_back({crc, len});
    root->children.push_back(std::move(right_child));

    const auto tree = make_tree(std::move(root));

    constexpr std::array<std::uint8_t, 3> prefix_bytes{0x48, 0x89, 0x5C};
    const auto buf = make_function_bytes(prefix_bytes, tail);
    CHECK(flirt::match_flirt(tree, buf));

    // With a prefix that matches neither child, nothing verifies
    constexpr std::array<std::uint8_t, 3> other_prefix{0x01, 0x02, 0x03};
    const auto miss = make_function_bytes(other_prefix, tail);
    CHECK_FALSE(flirt::match_flirt(tree, miss));
}

TEST_CASE("flirt_matcher: wildcard position accepts an arbitrary byte") {
    // Position 1 is a wildcard, so any byte there is accepted
    const auto prefix = papa_tests::pattern({0xE8, -1, -1, -1, -1, 0x90});

    constexpr std::array<std::uint8_t, 3> tail{0xAB, 0xCD, 0xEF};
    const std::uint16_t crc = flirt::flirt_crc16(tail);

    auto root = std::make_unique<flirt::FlirtNode>();
    root->pattern = prefix;
    root->leaf_modules.push_back({crc, static_cast<std::uint16_t>(tail.size())});
    const auto tree = make_tree(std::move(root));

    // Arbitrary bytes fill the wildcarded displacement positions
    constexpr std::array<std::uint8_t, 6> prefix_bytes{0xE8, 0x7F, 0x13, 0x00, 0x00, 0x90};
    const auto buf = make_function_bytes(prefix_bytes, tail);
    CHECK(flirt::match_flirt(tree, buf));

    // A different arbitrary byte at the wildcard still matches
    auto buf2 = buf;
    buf2[1] = 0x00U;
    CHECK(flirt::match_flirt(tree, buf2));

    // Changing a fixed (non-wildcard) byte breaks the match
    auto buf3 = buf;
    buf3[5] = 0x91U;
    CHECK_FALSE(flirt::match_flirt(tree, buf3));
}

TEST_CASE("flirt_matcher: tail_length zero verifies on empty subspan when pattern matches") {
    const auto prefix = papa_tests::pattern({0x90, 0x90});
    const std::uint16_t crc_of_nothing = flirt::flirt_crc16({});

    auto root = std::make_unique<flirt::FlirtNode>();
    root->pattern = prefix;
    root->leaf_modules.push_back({crc_of_nothing, 0U});
    const auto tree = make_tree(std::move(root));

    // Exactly the pattern region, no tail bytes. A zero-length CRC verifies
    std::vector<std::uint8_t> buf(flirt::kMaxPatternLength, 0x90U);
    CHECK(flirt::match_flirt(tree, buf));

    // A wrong stored CRC for the empty tail must not match
    auto bad_root = std::make_unique<flirt::FlirtNode>();
    bad_root->pattern = prefix;
    bad_root->leaf_modules.push_back({static_cast<std::uint16_t>(crc_of_nothing ^ 0x1U), 0U});
    const auto bad_tree = make_tree(std::move(bad_root));
    CHECK_FALSE(flirt::match_flirt(bad_tree, buf));
}

TEST_CASE("flirt_matcher: match_flirt_modules returns a pattern+CRC+tail-byte match with its references") {
    const auto prefix = papa_tests::pattern({0x55, 0x8B, 0xEC});
    constexpr std::array<std::uint8_t, 4> tail{0x11, 0x22, 0x33, 0x44};
    const std::uint16_t crc = flirt::flirt_crc16(tail);
    const auto len = static_cast<std::uint16_t>(tail.size());

    auto root = std::make_unique<flirt::FlirtNode>();
    root->pattern = prefix;
    flirt::FlirtModule m;
    m.tail_crc16  = crc;
    m.tail_length = len;
    m.names.push_back({0, "foo", flirt::FlirtNameType::kPublic});
    m.references.push_back({0x10U, "malloc"});
    // The tail-byte offset is relative to the end of the pattern and CRC region, so the
    // matcher reads kMaxPatternLength + crc_len + 2
    m.tail_bytes.push_back({0x02U, 0xABU});
    root->leaf_modules.push_back(std::move(m));
    const auto tree = make_tree(std::move(root));

    // 32-byte pattern region, then the 4-byte CRC tail, then a body that carries
    // the tail byte at its function-relative position
    std::vector<std::uint8_t> buf(flirt::kMaxPatternLength + tail.size() + 8U, 0x90U);
    buf[0] = 0x55U; buf[1] = 0x8BU; buf[2] = 0xECU;
    for (std::size_t i = 0; i < tail.size(); ++i) { buf[flirt::kMaxPatternLength + i] = tail[i]; }
    buf[flirt::kMaxPatternLength + tail.size() + 0x02U] = 0xABU;  // the required tail byte

    const auto hits = flirt::match_flirt_modules(tree, buf);
    REQUIRE(hits.size() == 1U);
    REQUIRE(hits[0]->references.size() == 1U);
    CHECK(hits[0]->references[0].name == "malloc");
    CHECK(hits[0]->references[0].offset == 0x10U);
}

TEST_CASE("flirt_matcher: a module whose tail byte mismatches is rejected") {
    // python-flirt applies tail bytes as a hard filter, so a module matching the pattern
    // and CRC is still eliminated when a recorded tail byte differs
    const auto prefix = papa_tests::pattern({0x55, 0x8B, 0xEC});
    constexpr std::array<std::uint8_t, 4> tail{0x11, 0x22, 0x33, 0x44};
    const std::uint16_t crc = flirt::flirt_crc16(tail);
    const auto len = static_cast<std::uint16_t>(tail.size());

    auto root = std::make_unique<flirt::FlirtNode>();
    root->pattern = prefix;
    flirt::FlirtModule m;
    m.tail_crc16  = crc;
    m.tail_length = len;
    m.names.push_back({0, "foo", flirt::FlirtNameType::kPublic});
    m.tail_bytes.push_back({0x02U, 0xABU});
    root->leaf_modules.push_back(std::move(m));
    const auto tree = make_tree(std::move(root));

    std::vector<std::uint8_t> buf(flirt::kMaxPatternLength + tail.size() + 8U, 0x90U);
    buf[0] = 0x55U; buf[1] = 0x8BU; buf[2] = 0xECU;
    for (std::size_t i = 0; i < tail.size(); ++i) { buf[flirt::kMaxPatternLength + i] = tail[i]; }

    const std::size_t tb_pos = flirt::kMaxPatternLength + tail.size() + 0x02U;
    buf[tb_pos] = 0x00U;  // not the required value
    CHECK(flirt::match_flirt_modules(tree, buf).empty());
    CHECK_FALSE(flirt::match_flirt(tree, buf));

    buf[tb_pos] = 0xABU;  // now it carries the required tail byte
    CHECK(flirt::match_flirt_modules(tree, buf).size() == 1U);
    CHECK(flirt::match_flirt(tree, buf));
}

TEST_CASE("flirt_matcher: two modules under one node, only the second CRC matches") {
    const auto prefix = papa_tests::pattern({0x40, 0x53});

    constexpr std::array<std::uint8_t, 6> tail{0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
    const std::uint16_t real_crc = flirt::flirt_crc16(tail);
    const auto len = static_cast<std::uint16_t>(tail.size());

    auto root = std::make_unique<flirt::FlirtNode>();
    root->pattern = prefix;
    // First module has a deliberately wrong CRC over the same window length
    root->leaf_modules.push_back({static_cast<std::uint16_t>(real_crc ^ 0xBEEFU), len});
    // Second module carries the correct CRC
    root->leaf_modules.push_back({real_crc, len});
    const auto tree = make_tree(std::move(root));

    constexpr std::array<std::uint8_t, 2> prefix_bytes{0x40, 0x53};
    const auto buf = make_function_bytes(prefix_bytes, tail);
    CHECK(flirt::match_flirt(tree, buf));
}
