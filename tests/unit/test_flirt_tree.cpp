#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/flirt/flirt_tree.h"

#include "test_support.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

namespace flirt = papa::features::extractors::papa_native::flirt;

TEST_CASE("flirt_tree: a pattern demands its fixed bytes and accepts anything at a wildcard") {
    // A negative entry is a wildcard
    struct Row {
        std::string_view          label;
        flirt::FlirtPattern       pattern;
        std::vector<std::uint8_t> data;
        bool                      matches;
    };
    const flirt::FlirtPattern empty;
    const auto exact    = papa_tests::pattern({0x48, 0x83, 0xEC});
    const auto wildcard = papa_tests::pattern({0x48, -1, 0xEC, -1});
    const std::vector<Row> rows{
        {"an empty pattern matches an empty buffer", empty, {}, true},
        {"an empty pattern matches any buffer", empty, {0x01, 0x02, 0x03, 0x04}, true},
        {"an exact pattern matches its bytes", exact, {0x48, 0x83, 0xEC, 0x28}, true},
        {"an exact pattern rejects a differing byte", exact, {0x48, 0x83, 0xED, 0x28}, false},
        {"an exact pattern rejects a shorter buffer", exact, {0x48, 0x83}, false},
        {"a wildcard accepts one byte", wildcard, {0x48, 0x83, 0xEC, 0x28}, true},
        {"a wildcard accepts another byte", wildcard, {0x48, 0x00, 0xEC, 0xFF}, true},
        {"a fixed position next to wildcards still differs", wildcard, {0x48, 0x83, 0xED, 0x28},
         false},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        CHECK(row.pattern.matches(row.data) == row.matches);
    }
}

TEST_CASE("flirt_tree: a tree reports its header, its root and the leaf modules across all its nodes") {
    // One module at the root, 2 at child a and 1 at a grandchild under child b
    auto root = std::make_unique<flirt::FlirtNode>();
    root->leaf_modules.push_back({0x1234U, 16U});
    auto child_a = std::make_unique<flirt::FlirtNode>();
    child_a->leaf_modules.push_back({0xAAAAU, 8U});
    child_a->leaf_modules.push_back({0xBBBBU, 8U});
    root->children.push_back(std::move(child_a));
    auto child_b = std::make_unique<flirt::FlirtNode>();
    auto grand   = std::make_unique<flirt::FlirtNode>();
    grand->leaf_modules.push_back({0xCCCCU, 4U});
    child_b->children.push_back(std::move(grand));
    root->children.push_back(std::move(child_b));
    flirt::FlirtHeader hdr;
    hdr.version = 10;
    const flirt::FlirtTree built{hdr, std::move(root)};
    const flirt::FlirtTree empty;

    struct Row {
        std::string_view        label;
        const flirt::FlirtTree* tree;
        bool                    has_root;
        std::size_t             modules;
        std::uint8_t            version;
    };
    const std::vector<Row> rows{
        {"a default-constructed tree is empty", &empty, false, 0, 0},
        {"module_count aggregates leaf modules across the tree", &built, true, 4, 10},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        CHECK((row.tree->root() != nullptr) == row.has_root);
        CHECK(row.tree->module_count() == row.modules);
        CHECK(row.tree->header().version == row.version);
    }
}

TEST_CASE("flirt_tree: FlirtTree is movable but not copyable") {
    static_assert(std::is_move_constructible_v<flirt::FlirtTree>);
    static_assert(std::is_move_assignable_v<flirt::FlirtTree>);
    static_assert(!std::is_copy_constructible_v<flirt::FlirtTree>);
    static_assert(!std::is_copy_assignable_v<flirt::FlirtTree>);
}
