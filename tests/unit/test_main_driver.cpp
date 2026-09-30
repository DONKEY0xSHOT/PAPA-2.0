#include <ostream>

#include "doctest.h"

#include "papa/main_driver.h"
#include "papa/version.h"

#include <array>
#include <iostream>
#include <sstream>
#include <streambuf>
#include <string>
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

TEST_CASE("run: --version prints the program file name and the release version like argparse") {
    papa::cli::Args args;
    args.show_version = true;
    args.argv0 = "tools/papa.exe";
    CHECK(run_capturing_stdout(args) == version_line("papa.exe"));
#if defined(_WIN32)
    args.argv0 = "C:\\tools\\papa.exe";
    CHECK(run_capturing_stdout(args) == version_line("papa.exe"));
#endif
}

TEST_CASE("run: --version names the program papa when argv[0] is empty") {
    papa::cli::Args args;
    args.show_version = true;
    CHECK(run_capturing_stdout(args) == version_line("papa"));
}

TEST_CASE("run: the first line of --help is the --version line") {
    papa::cli::Args args;
    args.show_help = true;
    args.argv0 = "/usr/bin/papa";
    const std::string out = run_capturing_stdout(args);
    CHECK(out.rfind(version_line("papa"), 0) == 0);
}
