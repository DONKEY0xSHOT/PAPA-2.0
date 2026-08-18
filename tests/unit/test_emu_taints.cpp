#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/emu/taints.h"

#include <cstdint>

namespace emu = papa::features::extractors::papa_native::emu;

// The taint registry allocates sentinel values for unknown emulator state. Taints
// live in a reserved high band, so they read as non-pointers and are never followed

TEST_CASE("emu taints: allocate produces values in the reserved band") {
    emu::TaintRegistry taints;
    const std::uint64_t a = taints.allocate(emu::TaintType::kUninitReg);
    const std::uint64_t b = taints.allocate(emu::TaintType::kApiCall);
    CHECK(a >= 0x41560000ULL);
    CHECK(b >= 0x41560000ULL);
    CHECK(a != b);
}

TEST_CASE("emu taints: the first allocations match vivisect's exact sequence") {
    // nextVivTaint = next(count(0x4156000F, 0x2000)) + 0x1000
    emu::TaintRegistry taints;
    CHECK(taints.allocate(emu::TaintType::kUninitReg) == 0x4156100FULL);
    CHECK(taints.allocate(emu::TaintType::kUninitReg) == 0x4156300FULL);
    CHECK(taints.allocate(emu::TaintType::kUninitReg) == 0x4156500FULL);
}

TEST_CASE("emu taints: lookup recovers the type and info of an allocation") {
    emu::TaintRegistry taints;
    const std::uint64_t v = taints.allocate(emu::TaintType::kImport, 0x401234);
    const std::optional<emu::TaintInfo> found = taints.lookup(v);
    REQUIRE(found.has_value());
    CHECK(found->type == emu::TaintType::kImport);
    CHECK(found->info == 0x401234ULL);
}

TEST_CASE("emu taints: lookup resolves a near-taint value within the masked page") {
    // getVivTaint masks the query, so a taint plus a small offset still resolves
    emu::TaintRegistry taints;
    const std::uint64_t v = taints.allocate(emu::TaintType::kApiCall);
    const std::optional<emu::TaintInfo> found = taints.lookup(v + 0x10);
    REQUIRE(found.has_value());
    CHECK(found->type == emu::TaintType::kApiCall);
}

TEST_CASE("emu taints: lookup of a non-taint address returns nothing") {
    emu::TaintRegistry taints;
    taints.allocate(emu::TaintType::kUninitReg);
    CHECK_FALSE(taints.lookup(0x00401000ULL).has_value());
}

TEST_CASE("emu taints: size reflects the number of allocations") {
    emu::TaintRegistry taints;
    CHECK(taints.size() == 0);
    taints.allocate(emu::TaintType::kUninitReg);
    taints.allocate(emu::TaintType::kUninitReg);
    CHECK(taints.size() == 2);
}
