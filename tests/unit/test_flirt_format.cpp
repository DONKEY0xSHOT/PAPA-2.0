#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/flirt/flirt_format.h"

#include <cstddef>
#include <cstdint>

namespace flirt = papa::features::extractors::papa_native::flirt;

TEST_CASE("flirt_format: kIdasgnMagic spells IDASGN with NUL pad") {
    REQUIRE(flirt::kIdasgnMagic.size() == 6);
    CHECK(flirt::kIdasgnMagic[0] == std::byte{'I'});
    CHECK(flirt::kIdasgnMagic[1] == std::byte{'D'});
    CHECK(flirt::kIdasgnMagic[2] == std::byte{'A'});
    CHECK(flirt::kIdasgnMagic[3] == std::byte{'S'});
    CHECK(flirt::kIdasgnMagic[4] == std::byte{'G'});
    CHECK(flirt::kIdasgnMagic[5] == std::byte{'N'});
}

TEST_CASE("flirt_format: supported versions are 8, 9, 10") {
    CHECK(flirt::is_supported_version(8));
    CHECK(flirt::is_supported_version(9));
    CHECK(flirt::is_supported_version(10));
    CHECK_FALSE(flirt::is_supported_version(0));
    CHECK_FALSE(flirt::is_supported_version(7));
    CHECK_FALSE(flirt::is_supported_version(11));
    CHECK_FALSE(flirt::is_supported_version(255));
}

TEST_CASE("flirt_format: limits sit within sane FLAIR bounds") {
    CHECK(flirt::kMaxPatternLength == 32U);
    CHECK(flirt::kMaxTreeDepth > 0U);
    CHECK(flirt::kMaxTreeDepth <= 256U);
}

TEST_CASE("flirt_format: feature flag bits match the FLAIR layout") {
    CHECK(static_cast<std::uint16_t>(flirt::FlirtFeature::kCompressed) == 0x0010U);
}
