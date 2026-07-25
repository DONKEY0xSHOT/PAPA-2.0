#include <cstdint>
#include <ostream>
#include <utility>
#include <vector>

#include "doctest.h"

#include "papa/features/extractors/papa_native/viv/location_db.h"

using papa::features::extractors::papa_native::viv::Location;
using papa::features::extractors::papa_native::viv::LocationDb;
using papa::features::extractors::papa_native::viv::LocType;

TEST_CASE("LocationDb::get_location returns the location containing an interior address") {
    LocationDb db;
    db.add_location(0x1000, 7, LocType::kOp);  // op spanning 0x1000..0x1007

    CHECK(db.get_location(0x1000).has_value());
    CHECK(db.get_location(0x1003).has_value());
    CHECK(db.get_location(0x1003)->va == 0x1000);   // interior maps to the op start
    CHECK(db.get_location(0x1006).has_value());       // last byte of the op
    CHECK_FALSE(db.get_location(0x1007).has_value()); // one past the op
    CHECK_FALSE(db.get_location(0x0FFF).has_value()); // just before

    CHECK(db.is_location(0x1000));         // a start
    CHECK_FALSE(db.is_location(0x1003));   // interior is not a start
    CHECK(db.location_type(0x1003) == LocType::kOp);
}

TEST_CASE("LocationDb re-adding a start replaces it, and del_location removes it") {
    // vivisect gates overlap at the caller (makeCode checks getLocation first), so
    // the db only needs to replace a same-start location and support deletion
    LocationDb db;
    CHECK_FALSE(db.get_location(0x2000).has_value());  // empty db

    db.add_location(0x2000, 4, LocType::kOp);
    db.add_location(0x2000, 4, LocType::kPointer);      // re-add at the same start
    CHECK(db.location_type(0x2000) == LocType::kPointer);

    db.del_location(0x2000);
    CHECK_FALSE(db.get_location(0x2000).has_value());
}

TEST_CASE("LocationDb::for_each_location visits every location in ascending start order") {
    LocationDb db;
    db.add_location(0x2000, 3, LocType::kOp);
    db.add_location(0x1000, 5, LocType::kOp);
    db.add_location(0x3000, 8, LocType::kPointer);

    std::vector<std::pair<std::uint64_t, LocType>> seen;
    db.for_each_location(
        [&seen](const Location& loc) { seen.emplace_back(loc.va, loc.type); });

    REQUIRE(seen.size() == 3);
    CHECK(seen[0].first == 0x1000);
    CHECK(seen[1].first == 0x2000);
    CHECK(seen[2].first == 0x3000);
    CHECK(seen[2].second == LocType::kPointer);
}
