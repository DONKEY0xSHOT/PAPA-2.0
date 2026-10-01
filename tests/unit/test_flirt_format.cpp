#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/flirt/flirt_format.h"

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace flirt = papa::features::extractors::papa_native::flirt;

TEST_CASE("flirt_format: the magic, supported versions, limits and feature bits match the FLAIR layout") {
    // The magic spells IDASGN
    const std::string_view idasgn = "IDASGN";
    REQUIRE(flirt::kIdasgnMagic.size() == idasgn.size());
    for (std::size_t i = 0; i < idasgn.size(); ++i) {
        CAPTURE(i);
        CHECK(flirt::kIdasgnMagic[i] == static_cast<std::byte>(idasgn[i]));
    }

    // Versions 8, 9 and 10 are supported and nothing around them
    struct Row {
        std::uint8_t version;
        bool         supported;
    };
    const std::vector<Row> versions{
        {8, true}, {9, true}, {10, true}, {0, false}, {7, false}, {11, false}, {255, false},
    };
    for (const Row& row : versions) {
        CAPTURE(static_cast<int>(row.version));
        CHECK(flirt::is_supported_version(row.version) == row.supported);
    }

    // The limits sit within sane FLAIR bounds
    CHECK(flirt::kMaxPatternLength == 32U);
    CHECK(flirt::kMaxTreeDepth > 0U);
    CHECK(flirt::kMaxTreeDepth <= 256U);
    CHECK(static_cast<std::uint16_t>(flirt::FlirtFeature::kCompressed) == 0x0010U);
}
