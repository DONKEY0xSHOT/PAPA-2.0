#include <cstdint>
#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/viv/xref_db.h"

namespace pv = papa::features::extractors::papa_native::viv;

TEST_CASE("XrefDb records and queries code xrefs by from and to") {
    pv::XrefDb db;
    db.add_code_xref(0x1000, 0x1010, /*branch_flags=*/0x2);   // a conditional edge
    db.add_code_xref(0x1000, 0x1005, /*branch_flags=*/0x10);  // its fall-through

    const auto& from = db.code_xrefs_from(0x1000);
    CHECK(from.size() == 2);
    CHECK(db.has_code_xref_to(0x1010));
    CHECK(db.has_code_xref_to(0x1005));
    CHECK_FALSE(db.has_code_xref_to(0x2000));

    // A repeated (from, to) is not recorded twice, matching vivisect addXref
    db.add_code_xref(0x1000, 0x1010, 0x2);
    CHECK(db.code_xrefs_from(0x1000).size() == 2);

    // An address with no outgoing edges returns an empty list
    CHECK(db.code_xrefs_from(0x9999).empty());
}
