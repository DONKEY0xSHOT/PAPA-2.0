#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace papa::cli {

// Output verbosity for the text renderer
// --json overrides these and triggers the JSON renderer instead
enum class OutputMode : std::uint8_t {
    kDefault,
    kVerbose,
    kVverbose,
    kJson,
};

struct Args {
    std::filesystem::path  sample_path;
    std::filesystem::path  rules_dir{"data/rules"};
    std::filesystem::path  output_path;        // empty means stdout
    OutputMode             output{OutputMode::kDefault};
    bool                   quiet{false};
    bool                   show_help{false};
    bool                   show_version{false};
};

// Exit codes
// Matching CAPA's convention so external scripts can rely on the same numbers
inline constexpr int kExitOk                 = 0;
inline constexpr int kExitUsage              = 2;
inline constexpr int kExitFileLimitation     = 10;
inline constexpr int kExitMissingFile        = 11;
inline constexpr int kExitInvalidFileType    = 12;
inline constexpr int kExitInvalidRule        = 13;
inline constexpr int kExitUnexpectedFailure  = 64;

// Parsing result is either a populated Args or an error message + suggested code
struct ParseResult {
    Args         args;
    std::string  error;            // empty on success
    int          exit_code{kExitOk};
};

// Parse argv and produce a ParseResult
// argv0 is excluded
// Callers should pass (argv+1, argc-1) from main
[[nodiscard]] ParseResult
parse_args(int argc, const char* const* argv);

// Run the full analysis pipeline given parsed args
// Returns one of the kExit* codes and never throws across this boundary
// Recoverable errors print to stderr while normal output goes to stdout
[[nodiscard]] int run(const Args& args);

}  // namespace papa::cli
