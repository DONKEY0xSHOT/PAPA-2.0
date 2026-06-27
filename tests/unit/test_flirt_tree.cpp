#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/flirt/flirt_tree.h"

#include <array>
#include <cstdint>
#include <memory>

namespace flirt = papa::features::extractors::papa_native::flirt;

namespace {

flirt::FlirtPattern make_pattern(std::initializer_list<int> bytes) {
    flirt::FlirtPattern pat;
    pat.length = 0;
    for (int b : bytes) {
        if (b < 0) {
            pat.wildcard.set(pat.length);
        } else {
            pat.bytes[pat.length] = static_cast<std::uint8_t>(b);
        }
        pat.length = static_cast<std::uint8_t>(pat.length + 1U);
    }
    return pat;
}

}  // namespace

TEST_CASE("flirt_tree: empty pattern matches empty buffer and any buffer") {
    flirt::FlirtPattern pat;
    CHECK(pat.matches({}));
    constexpr std::array<std::uint8_t, 4> data{0x01, 0x02, 0x03, 0x04};
    CHECK(pat.matches(data));
}

TEST_CASE("flirt_tree: pattern without wildcards demands exact match") {
    const auto pat = make_pattern({0x48, 0x83, 0xEC});
    constexpr std::array<std::uint8_t, 4> ok      = {0x48, 0x83, 0xEC, 0x28};
    constexpr std::array<std::uint8_t, 4> diff    = {0x48, 0x83, 0xED, 0x28};
    constexpr std::array<std::uint8_t, 2> shorter = {0x48, 0x83};
    CHECK(pat.matches(ok));
    CHECK_FALSE(pat.matches(diff));
    CHECK_FALSE(pat.matches(shorter));
}

TEST_CASE("flirt_tree: pattern with wildcards matches any byte at masked positions") {
    const auto pat = make_pattern({0x48, -1, 0xEC, -1});  // -1 = wildcard
    constexpr std::array<std::uint8_t, 4> a = {0x48, 0x83, 0xEC, 0x28};
    constexpr std::array<std::uint8_t, 4> b = {0x48, 0x00, 0xEC, 0xFF};
    constexpr std::array<std::uint8_t, 4> c = {0x48, 0x83, 0xED, 0x28};  // fixed pos differs
    CHECK(pat.matches(a));
    CHECK(pat.matches(b));
    CHECK_FALSE(pat.matches(c));
}

TEST_CASE("flirt_tree: default-constructed tree is empty") {
    flirt::FlirtTree tree;
    CHECK(tree.root() == nullptr);
    CHECK(tree.module_count() == 0U);
    CHECK(tree.header().version == 0U);
}

TEST_CASE("flirt_tree: module_count aggregates leaf modules across the tree") {
    auto root = std::make_unique<flirt::FlirtNode>();
    root->leaf_modules.push_back({0x1234U, 16U});  // 1 module at root

    auto child_a = std::make_unique<flirt::FlirtNode>();
    child_a->leaf_modules.push_back({0xAAAAU, 8U});
    child_a->leaf_modules.push_back({0xBBBBU, 8U});  // 2 at child a
    root->children.push_back(std::move(child_a));

    auto child_b = std::make_unique<flirt::FlirtNode>();
    auto grand   = std::make_unique<flirt::FlirtNode>();
    grand->leaf_modules.push_back({0xCCCCU, 4U});   // 1 in deep child
    child_b->children.push_back(std::move(grand));
    root->children.push_back(std::move(child_b));

    flirt::FlirtHeader hdr;
    hdr.version = 10;
    flirt::FlirtTree tree{hdr, std::move(root)};
    CHECK(tree.module_count() == 4U);
    CHECK(tree.header().version == 10U);
    CHECK(tree.root() != nullptr);
}

TEST_CASE("flirt_tree: FlirtTree is movable but not copyable") {
    static_assert(std::is_move_constructible_v<flirt::FlirtTree>);
    static_assert(std::is_move_assignable_v<flirt::FlirtTree>);
    static_assert(!std::is_copy_constructible_v<flirt::FlirtTree>);
    static_assert(!std::is_copy_assignable_v<flirt::FlirtTree>);
}
