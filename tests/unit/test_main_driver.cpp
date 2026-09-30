#include <ostream>

#include "doctest.h"

#include "papa/main_driver.h"

#include <array>
#include <string>
#include <vector>

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

TEST_CASE("parse_args: argv records every argument including option values like capa") {
    const std::array<const char*, 6> argv{"--json", "-r", "x", "-o", "y", "s.exe"};
    const auto res = parse_args(static_cast<int>(argv.size()), argv.data());
    REQUIRE(res.error.empty());
    const std::vector<std::string> expected{"--json", "-r", "x", "-o", "y", "s.exe"};
    CHECK(res.args.argv == expected);
}

TEST_CASE("parse_args: a non-positive argc records no arguments") {
    const std::array<const char*, 1> argv{"s.exe"};
    for (const int argc : {0, -1}) {
        const auto res = parse_args(argc, argv.data());
        CHECK(res.error.empty());
        CHECK(res.args.argv.empty());
    }
}
