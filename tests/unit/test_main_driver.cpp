#include <ostream>

#include "doctest.h"

#include "papa/main_driver.h"
#include "papa/version.h"

#include <array>
#include <iostream>
#include <optional>
#include <sstream>
#include <streambuf>
#include <string>
#include <string_view>
#include <vector>

using papa::cli::parse_args;

namespace {

// Run the CLI and return what it printed on stdout
[[nodiscard]] std::string run_capturing_stdout(const papa::cli::Args& args) {
    std::ostringstream captured;
    std::streambuf* const previous = std::cout.rdbuf(captured.rdbuf());
    const int rc = papa::cli::run(args);
    std::cout.rdbuf(previous);
    CHECK(rc == papa::cli::kExitOk);
    return captured.str();
}

[[nodiscard]] std::string version_line(const std::string& prog) {
    return prog + " " + std::string(papa::version::version()) + "\n";
}

}  // namespace

TEST_CASE("parse_args: -r and --rules set the rules directory, which stays unset without them so the embedded rules load") {
    struct Row {
        std::string_view                label;
        std::vector<const char*>        argv;
        std::optional<std::string_view> rules_dir;
    };
    const std::vector<Row> rows{
        {"no -r", {"sample.exe"}, std::nullopt},
        {"-r", {"sample.exe", "-r", "my-rules"}, "my-rules"},
        {"--rules", {"sample.exe", "--rules", "my-rules"}, "my-rules"},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto res = parse_args(static_cast<int>(row.argv.size()), row.argv.data());
        REQUIRE(res.error.empty());
        CHECK(res.args.rules_dir.has_value() == row.rules_dir.has_value());
        if (res.args.rules_dir.has_value() && row.rules_dir.has_value()) {
            CHECK(res.args.rules_dir->string() == *row.rules_dir);
        }
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

TEST_CASE("run: --version prints the program file name, or papa without one, and the release version like argparse") {
    struct Row {
        std::string_view label;
        std::string      argv0;
        std::string      prog;
    };
    const std::vector<Row> rows{
        {"a relative path", "tools/papa.exe", "papa.exe"},
#if defined(_WIN32)
        {"a Windows path", "C:\\tools\\papa.exe", "papa.exe"},
#endif
        {"an empty argv[0]", "", "papa"},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        papa::cli::Args args;
        args.show_version = true;
        args.argv0 = row.argv0;
        CHECK(run_capturing_stdout(args) == version_line(row.prog));
    }
}

TEST_CASE("run: the first line of --help is the --version line") {
    papa::cli::Args args;
    args.show_help = true;
    args.argv0 = "/usr/bin/papa";
    const std::string out = run_capturing_stdout(args);
    CHECK(out.rfind(version_line("papa"), 0) == 0);
}
