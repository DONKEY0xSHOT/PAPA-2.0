#include "papa/version.h"

#include <ostream>
#include <string_view>

#include "doctest.h"

TEST_CASE("papa::version::version is the release version the build stamped in") {
    const std::string_view v = papa::version::version();
    CHECK_FALSE(v.empty());
    CHECK(v != "PAPA_VERSION");
}
