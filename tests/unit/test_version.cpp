#include "papa/version.h"

#include <ostream>
#include <string>
#include <string_view>

#include "doctest.h"

TEST_CASE("papa::version::kVersionString is non-empty and dot-separated") {
    const auto v = papa::version::kVersionString;
    CHECK_FALSE(v.empty());

    std::size_t dot_count = 0;
    for (char c : v) {
        if (c == '.') {
            ++dot_count;
        } else {
            CHECK((c >= '0' && c <= '9'));
        }
    }
    CHECK(dot_count == 2);
}

TEST_CASE("papa::version component numbers match the string") {
    const std::string expected =
        std::to_string(papa::version::kMajor) + "." +
        std::to_string(papa::version::kMinor) + "." +
        std::to_string(papa::version::kPatch);
    CHECK(std::string_view{expected} == papa::version::kVersionString);
}

TEST_CASE("papa::version::banner includes product name and version") {
    const std::string_view b = papa::version::banner();
    CHECK(b.find(papa::version::kProductName)   != std::string_view::npos);
    CHECK(b.find(papa::version::kVersionString) != std::string_view::npos);
    CHECK(b.back() != '\0');
}

TEST_CASE("papa::version::kProductName is 'PAPA'") {
    CHECK(papa::version::kProductName == "PAPA");
}
