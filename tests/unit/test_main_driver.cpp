#include <ostream>

#include "doctest.h"

#include "papa/main_driver.h"

#include <array>

using papa::cli::parse_args;

TEST_CASE("parse_args: without -r the rules directory is unset so the embedded rules load") {
    const std::array<const char*, 1> argv{"sample.exe"};
    const auto res = parse_args(static_cast<int>(argv.size()), argv.data());
    REQUIRE(res.error.empty());
    CHECK_FALSE(res.args.rules_dir.has_value());
}

TEST_CASE("parse_args: -r and --rules set the rules directory") {
    for (const char* flag : {"-r", "--rules"}) {
        const std::array<const char*, 3> argv{"sample.exe", flag, "my-rules"};
        const auto res = parse_args(static_cast<int>(argv.size()), argv.data());
        REQUIRE(res.error.empty());
        REQUIRE(res.args.rules_dir.has_value());
        CHECK(res.args.rules_dir->string() == "my-rules");
    }
}
