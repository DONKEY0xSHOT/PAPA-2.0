#include <ostream>

#include "doctest.h"

#include "papa/main_driver.h"
#include "papa/version.h"

#include "pe_builder.h"
#include "test_support.h"

#include <array>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using papa::cli::OutputMode;
using papa::cli::parse_args;

namespace {

// Run the CLI and return what it printed on stdout
[[nodiscard]] std::string run_capturing_stdout(const papa::cli::Args& args) {
    const papa_tests::StreamCapture out(std::cout);
    CHECK(papa::cli::run(args) == papa::cli::kExitOk);
    return out.text();
}

[[nodiscard]] std::string version_line(const std::string& prog) {
    return prog + " " + std::string(papa::version::version()) + "\n";
}

}  // namespace

TEST_CASE("parse_args: each flag sets its field, and a missing value or a stray argument is a usage error") {
    struct Row {
        std::string_view                label;
        std::vector<const char*>        argv;
        std::string_view                sample      = {};
        std::optional<std::string_view> rules_dir   = {};
        std::string_view                output_path = {};
        OutputMode                      mode        = OutputMode::kDefault;
        bool                            quiet       = false;
        bool                            help        = false;
        bool                            version     = false;
        std::string_view                error       = {};
    };
    const std::vector<Row> rows{
        {.label = "a bare sample uses the embedded rules", .argv = {"s.exe"}, .sample = "s.exe"},
        {.label = "-r", .argv = {"s.exe", "-r", "my-rules"}, .sample = "s.exe",
         .rules_dir = "my-rules"},
        {.label = "--rules", .argv = {"s.exe", "--rules", "my-rules"}, .sample = "s.exe",
         .rules_dir = "my-rules"},
        {.label = "-o", .argv = {"s.exe", "-o", "out.txt"}, .sample = "s.exe",
         .output_path = "out.txt"},
        {.label = "--output", .argv = {"--output", "out.txt", "s.exe"}, .sample = "s.exe",
         .output_path = "out.txt"},
        {.label = "-j", .argv = {"-j", "s.exe"}, .sample = "s.exe", .mode = OutputMode::kJson},
        {.label = "--json", .argv = {"--json", "s.exe"}, .sample = "s.exe",
         .mode = OutputMode::kJson},
        {.label = "-v", .argv = {"-v", "s.exe"}, .sample = "s.exe", .mode = OutputMode::kVerbose},
        {.label = "--verbose", .argv = {"--verbose", "s.exe"}, .sample = "s.exe",
         .mode = OutputMode::kVerbose},
        {.label = "-vv", .argv = {"-vv", "s.exe"}, .sample = "s.exe",
         .mode = OutputMode::kVverbose},
        {.label = "--vverbose", .argv = {"--vverbose", "s.exe"}, .sample = "s.exe",
         .mode = OutputMode::kVverbose},
        {.label = "the last mode flag wins", .argv = {"-j", "-v", "s.exe"}, .sample = "s.exe",
         .mode = OutputMode::kVerbose},
        {.label = "-q", .argv = {"-q", "s.exe"}, .sample = "s.exe", .quiet = true},
        {.label = "--quiet", .argv = {"--quiet", "s.exe"}, .sample = "s.exe", .quiet = true},
        {.label = "-h", .argv = {"-h"}, .help = true},
        {.label = "--help", .argv = {"--help"}, .help = true},
        {.label = "--version", .argv = {"--version"}, .version = true},
        {.label = "-r without a directory", .argv = {"s.exe", "-r"},
         .error = "--rules requires a directory argument"},
        {.label = "-o without a path", .argv = {"s.exe", "-o"},
         .error = "--output requires a path argument"},
        {.label = "an unknown flag", .argv = {"--bogus", "s.exe"},
         .error = "unrecognized argument: --bogus"},
        {.label = "a second positional", .argv = {"a.exe", "b.exe"},
         .error = "unrecognized argument: b.exe"},
        {.label = "an empty argument", .argv = {""}, .error = "unrecognized argument: "},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto res = parse_args(static_cast<int>(row.argv.size()), row.argv.data());
        CHECK(res.error == row.error);
        if (!row.error.empty()) {
            CHECK(res.exit_code == papa::cli::kExitUsage);
            continue;
        }
        CHECK(res.exit_code == papa::cli::kExitOk);
        CHECK(res.args.sample_path == std::filesystem::path(row.sample));
        CHECK(res.args.rules_dir.has_value() == row.rules_dir.has_value());
        if (res.args.rules_dir.has_value() && row.rules_dir.has_value()) {
            CHECK(res.args.rules_dir->string() == *row.rules_dir);
        }
        CHECK(res.args.output_path == std::filesystem::path(row.output_path));
        CHECK(res.args.output == row.mode);
        CHECK(res.args.quiet == row.quiet);
        CHECK(res.args.show_help == row.help);
        CHECK(res.args.show_version == row.version);
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

TEST_CASE("run: each failure ends with its exit code and names the cause on stderr") {
    using papa_tests::rule_yaml;
    using papa_tests::write_file;
    const papa_tests::TempDir dir;
    const auto&               root = dir.path();
    papa_tests::PeBuilder     b;
    b.code = {0x33, 0xC0, 0xC3};
    write_file(root / "sample.exe", b.build());
    write_file(root / "notpe.exe", "not a portable executable");
    std::filesystem::create_directories(root / "a_dir");
    // Every PE has a .text section, so this rule makes any sample a static limitation
    write_file(root / "limited" / "packed.yml",
               rule_yaml("packed", "file", {"section: .text"}, "internal/limitation/static"));
    write_file(root / "plain" / "text.yml", rule_yaml("has text", "file", {"section: .text"}));

    struct Row {
        std::string_view                label;
        std::string_view                sample;
        std::optional<std::string_view> rules;
        std::string_view                output;
        bool                            quiet;
        int                             exit_code;
        std::string_view                stderr_text;
    };
    const std::vector<Row> rows{
        {"no sample path", "", std::nullopt, "", false, papa::cli::kExitUsage,
         "error: missing sample path"},
        {"a missing sample", "missing.exe", std::nullopt, "", false, papa::cli::kExitMissingFile,
         "error: sample not found"},
        {"a directory as the sample", "a_dir", std::nullopt, "", false,
         papa::cli::kExitMissingFile, "error: cannot read sample"},
        {"a file that is not a PE", "notpe.exe", std::nullopt, "", false,
         papa::cli::kExitInvalidFileType, "error: not a parseable PE file"},
        {"a missing rules directory", "sample.exe", "no_rules", "", false,
         papa::cli::kExitInvalidRule, "error: rules directory not found"},
        {"a rules path that is a file", "sample.exe", "notpe.exe", "", false,
         papa::cli::kExitInvalidRule, "error: failed to load rules: rules path is not a directory"},
        {"a static limitation", "sample.exe", "limited", "", false,
         papa::cli::kExitFileLimitation, "static-only limitation rule matched"},
        {"a static limitation with -q", "sample.exe", "limited", "", true,
         papa::cli::kExitFileLimitation, ""},
        {"an output path that cannot be opened", "sample.exe", "plain", "no_dir/out.txt", false,
         papa::cli::kExitUnexpectedFailure, "error: cannot open output path"},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        papa::cli::Args args;
        if (!row.sample.empty()) { args.sample_path = root / row.sample; }
        if (row.rules.has_value()) { args.rules_dir = root / *row.rules; }
        if (!row.output.empty()) { args.output_path = root / row.output; }
        args.quiet = row.quiet;

        const papa_tests::StreamCapture out(std::cout);
        const papa_tests::StreamCapture err(std::cerr);
        CHECK(papa::cli::run(args) == row.exit_code);
        if (row.stderr_text.empty()) {
            CHECK(err.text().empty());
        } else {
            CHECK(err.text().find(row.stderr_text) != std::string::npos);
        }
    }
}
