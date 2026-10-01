#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/emu/taints.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace emu = papa::features::extractors::papa_native::emu;

// The taint registry allocates sentinel values for unknown emulator state. Taints
// live in a reserved high band, so they read as non-pointers and are never followed

TEST_CASE("emu taints: allocations follow vivisect's sequence inside the reserved band and are counted") {
    // nextVivTaint = next(count(0x4156000F, 0x2000)) + 0x1000
    struct Row {
        std::string_view            label;
        std::vector<emu::TaintType> types;
        std::vector<std::uint64_t>  expected;
    };
    const std::vector<Row> rows{
        {"none leaves the registry empty", {}, {}},
        {"different types still take the next distinct value",
         {emu::TaintType::kUninitReg, emu::TaintType::kApiCall}, {0x4156100FULL, 0x4156300FULL}},
        {"the first allocations match vivisect's exact sequence",
         {emu::TaintType::kUninitReg, emu::TaintType::kUninitReg, emu::TaintType::kUninitReg},
         {0x4156100FULL, 0x4156300FULL, 0x4156500FULL}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        emu::TaintRegistry taints;
        for (std::size_t i = 0; i < row.types.size(); ++i) {
            CAPTURE(i);
            const std::uint64_t v = taints.allocate(row.types[i]);
            CHECK(v >= 0x41560000ULL);
            CHECK(v == row.expected[i]);
        }
        CHECK(taints.size() == row.types.size());
    }
}

TEST_CASE("emu taints: lookup recovers an allocation's type and info, within its masked page only") {
    // getVivTaint masks the query, so a taint plus a small offset still resolves
    using Query = std::uint64_t (*)(std::uint64_t allocated);
    struct Row {
        std::string_view              label;
        emu::TaintType                type;
        std::uint64_t                 info;
        Query                         query;
        std::optional<emu::TaintType> found_type;
        std::uint64_t                 found_info;
    };
    const std::vector<Row> rows{
        {"the allocated value itself", emu::TaintType::kImport, 0x401234,
         [](std::uint64_t v) { return v; }, emu::TaintType::kImport, 0x401234ULL},
        {"a near-taint value within the masked page", emu::TaintType::kApiCall, 0,
         [](std::uint64_t v) { return v + 0x10; }, emu::TaintType::kApiCall, 0},
        {"a non-taint address", emu::TaintType::kUninitReg, 0,
         [](std::uint64_t) { return std::uint64_t{0x00401000}; }, std::nullopt, 0},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        emu::TaintRegistry taints;
        const std::uint64_t v = taints.allocate(row.type, row.info);
        const std::optional<emu::TaintInfo> found = taints.lookup(row.query(v));
        CHECK(found.has_value() == row.found_type.has_value());
        if (found.has_value() && row.found_type.has_value()) {
            CHECK(found->type == *row.found_type);
            CHECK(found->info == row.found_info);
        }
    }
}
