#include "papa/main_driver.h"

#include "papa/capabilities/common.h"
#include "papa/capabilities/static_.h"
#include "papa/exceptions.h"
#include "papa/features/address.h"
#include "papa/features/extractors/papa_native/backend.h"
#include "papa/features/extractors/papa_native/extractor.h"
#include "papa/features/extractors/pefile_extractor.h"
#include "papa/loader.h"
#include "papa/pe/pe_image.h"
#include "papa/pe/pe_parser.h"
#include "papa/render/json.h"
#include "papa/render/result_document.h"
#include "papa/render/text.h"
#include "papa/rules/ruleset.h"
#include "papa/version.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

#if defined(_WIN32)
#  include <cstdio>
#  include <io.h>
#endif

namespace papa::cli {

namespace {

constexpr std::string_view kUsage =
    "Usage: papa [OPTIONS] <sample>\n"
    "\n"
    "Options:\n"
    "  -r, --rules <dir>   Rule directory (default: data/rules)\n"
    "  -j, --json          Emit JSON output\n"
    "  -v, --verbose       Verbose text output\n"
    "      --vverbose      Most verbose text output, includes rule sources\n"
    "  -o, --output <path> Write report to a file instead of stdout\n"
    "  -q, --quiet         Suppress informational messages on stderr\n"
    "      --timing        Print a per-phase wall-clock breakdown on stderr\n"
    "  -h, --help          Show this message and exit\n"
    "      --version       Print version information and exit\n"
    "\n"
    "Examples:\n"
    "  papa sample.exe -r capa-rules-9.4.0\n"
    "  papa sample.exe -j -o report.json -r capa-rules-9.4.0\n";

// Slurp the whole file into an owned buffer
// Returns an empty optional on any IO failure
// Specific errors are surfaced separately by the caller via stderr
[[nodiscard]] std::optional<std::vector<std::byte>>
read_entire_file(const std::filesystem::path& path) {
    std::error_code ec;
    const auto sz = std::filesystem::file_size(path, ec);
    if (ec) { return std::nullopt; }

    std::vector<std::byte> buf;
    buf.resize(static_cast<std::size_t>(sz));
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) { return std::nullopt; }
    ifs.read(reinterpret_cast<char*>(buf.data()),
             static_cast<std::streamsize>(buf.size()));
    if (ifs.gcount() != static_cast<std::streamsize>(buf.size())) {
        return std::nullopt;
    }
    return buf;
}

using SteadyClock = std::chrono::steady_clock;

// Wall-clock accumulator behind --timing
// Phases are appended in completion order so the report reads as a timeline,
// and a disabled log does no work beyond an early return
class PhaseLog {
public:
    explicit PhaseLog(bool enabled) noexcept : enabled_{enabled} {}

    [[nodiscard]] bool enabled() const noexcept { return enabled_; }

    // Close a phase that began at start and file it under name
    void record(std::string_view name, SteadyClock::time_point start) {
        if (!enabled_) { return; }
        const std::chrono::duration<double> span = SteadyClock::now() - start;
        phases_.emplace_back(std::string(name), span.count());
    }

    void report(std::ostream& out) const {
        if (!enabled_ || phases_.empty()) { return; }
        double      total = 0.0;
        std::size_t width = 5U;
        for (const auto& [name, secs] : phases_) {
            total += secs;
            width = std::max(width, name.size());
        }
        const int label_width = static_cast<int>(width);
        out << "\npapa phase timing\n";
        for (const auto& [name, secs] : phases_) {
            const double share = total > 0.0 ? secs / total * 100.0 : 0.0;
            out << "  " << std::left << std::setw(label_width) << name
                << std::right << std::fixed << std::setprecision(3)
                << std::setw(10) << secs << " s"
                << std::setw(7) << std::setprecision(1) << share << " %\n";
        }
        out << "  " << std::left << std::setw(label_width) << "TOTAL"
            << std::right << std::fixed << std::setprecision(3)
            << std::setw(10) << total << " s\n";
    }

private:
    bool                                        enabled_;
    std::vector<std::pair<std::string, double>> phases_;
};

// True when stdout is an interactive console rather than a file or pipe.
// capa colors its report only in this case, so PAPA does the same
[[nodiscard]] bool stdout_is_terminal() noexcept {
#if defined(_WIN32)
    return _isatty(_fileno(stdout)) != 0;
#else
    return false;
#endif
}

}  // namespace

ParseResult parse_args(int argc, const char* const* argv) {
    ParseResult res;
    Args& a = res.args;

    for (int i = 0; i < argc; ++i) {
        const std::string_view arg{argv[i]};

        // Keep every argument verbatim so the report can echo the command line
        a.argv.emplace_back(arg);

        if (arg == "--help" || arg == "-h") { a.show_help = true; continue; }
        if (arg == "--version")             { a.show_version = true; continue; }
        if (arg == "--quiet" || arg == "-q") { a.quiet = true; continue; }
        if (arg == "--timing")              { a.timing = true; continue; }
        if (arg == "--json"  || arg == "-j") { a.output = OutputMode::kJson; continue; }
        if (arg == "--verbose" || arg == "-v") {
            // -v on its own gives verbose
            // --vverbose has its own branch below
            a.output = OutputMode::kVerbose;
            continue;
        }
        if (arg == "--vverbose" || arg == "-vv") {
            a.output = OutputMode::kVverbose;
            continue;
        }
        if (arg == "--rules" || arg == "-r") {
            if (i + 1 >= argc) {
                res.error     = "--rules requires a directory argument";
                res.exit_code = kExitUsage;
                return res;
            }
            a.rules_dir = argv[++i];
            continue;
        }
        if (arg == "--output" || arg == "-o") {
            if (i + 1 >= argc) {
                res.error     = "--output requires a path argument";
                res.exit_code = kExitUsage;
                return res;
            }
            a.output_path = argv[++i];
            continue;
        }

        // First non-flag positional is the sample path
        if (a.sample_path.empty() && !arg.empty() && arg.front() != '-') {
            a.sample_path = std::filesystem::path(std::string(arg));
            continue;
        }

        res.error     = std::string("unrecognized argument: ").append(arg);
        res.exit_code = kExitUsage;
        return res;
    }
    return res;
}

int run(const Args& args) {
    if (args.show_version) {
        std::cout << version::banner() << '\n';
        return kExitOk;
    }
    if (args.show_help) {
        std::cout << version::banner() << "\n\n" << kUsage;
        return kExitOk;
    }

    if (args.sample_path.empty()) {
        std::cerr << "error: missing sample path\n\n" << kUsage;
        return kExitUsage;
    }
    if (!std::filesystem::exists(args.sample_path)) {
        std::cerr << "error: sample not found: " << args.sample_path << '\n';
        return kExitMissingFile;
    }

    PhaseLog timing{args.timing};

    auto mark = SteadyClock::now();
    auto sample_buf_opt = read_entire_file(args.sample_path);
    if (!sample_buf_opt.has_value()) {
        std::cerr << "error: cannot read sample: " << args.sample_path << '\n';
        return kExitMissingFile;
    }
    if (sample_buf_opt->size() > constants::kMaxSampleBytes) {
        std::cerr << "error: sample is too large to analyze: "
                  << sample_buf_opt->size() << " bytes\n";
        return kExitInvalidFileType;
    }
    timing.record("read sample", mark);

    mark = SteadyClock::now();
    // The buffer moves into the image rather than the parser reading the file a
    // second time. Two copies of the sample used to be live at once, which on a
    // large file is the largest allocation the process makes
    auto image = pe::PeParser::parse(std::move(*sample_buf_opt));
    if (!image) {
        std::cerr << "error: not a parseable PE file: "
                  << image.error().detail << '\n';
        return kExitInvalidFileType;
    }
    const std::span<const std::byte> sample_buf = image->raw_buffer();
    timing.record("parse PE", mark);

    if (!std::filesystem::exists(args.rules_dir)) {
        std::cerr << "error: rules directory not found: " << args.rules_dir
                  << '\n';
        return kExitInvalidRule;
    }
    mark = SteadyClock::now();
    auto ruleset = rules::RuleSet::from_directory(args.rules_dir);
    if (!ruleset) {
        std::cerr << "error: failed to load rules: "
                  << ruleset.error().detail << '\n';
        return kExitInvalidRule;
    }
    timing.record("load rules", mark);

    // capa colors its text report only for an interactive console, and only when
    // the report goes to stdout rather than a file
    const bool color = args.output_path.empty() && stdout_is_terminal();

    // The file features are a pure function of the parsed image, and both the
    // limitation pre-pass and the full pipeline need exactly the same set, so
    // carve the file once and share it
    mark = SteadyClock::now();
    features::extractors::PefileFeatureExtractor pe_only(*image);
    const auto file_features = pe_only.extract_file_features();
    timing.record("file features", mark);

    // First-pass file-only check for static-limitation rules
    {
        // Only the limitation gate runs here. Its verdict is the single thing
        // this pass decides, and the full file-scope result would be discarded
        mark = SteadyClock::now();
        auto gate_caps =
            capabilities::find_limitation_capabilities(*ruleset, pe_only, &file_features);
        if (!gate_caps) {
            std::cerr << "error: file-scope match failed: "
                      << gate_caps.error().detail << '\n';
            return kExitUnexpectedFailure;
        }
        timing.record("file pre-pass", mark);
        if (capabilities::has_static_limitation(*ruleset, *gate_caps)) {
            // The report needs every file-scope match, not just the gate, so
            // pay for the full pass on the rare path that actually renders one
            auto file_caps =
                capabilities::find_file_capabilities(*ruleset, pe_only, &file_features);
            if (!file_caps) {
                std::cerr << "error: file-scope match failed: "
                          << file_caps.error().detail << '\n';
                return kExitUnexpectedFailure;
            }
            if (!args.quiet) {
                std::cerr << "static-only limitation rule matched; "
                          << "consider dynamic analysis\n";
            }
            // The user still gets a report containing the limitation hit
            // but the code-extractor pass is skipped because results would be misleading
            std::vector<std::string> rules_paths{args.rules_dir.string()};
            auto meta = collect_metadata(
                std::span<const std::byte>(sample_buf),
                args.sample_path,
                args.argv,
                std::move(rules_paths),
                *image,
                capabilities::static_::StaticCapabilities{},
                pe_only);
            auto doc = render::build_document(std::move(meta), *ruleset, file_caps->matches);
            if (args.output == OutputMode::kJson) {
                // capa emits compact JSON (model_dump_json) then a trailing newline
                render::json::render(doc, std::cout, /*pretty=*/false);
                std::cout << '\n';
            } else {
                render::text::render(doc, std::cout, render::text::Verbosity::kDefault, color);
            }
            timing.report(std::cerr);
            return kExitFileLimitation;
        }
    }

    // Full code pipeline
    mark = SteadyClock::now();
    auto backend = features::extractors::papa_native::PapaNativeBackend::build(*image);
    if (!backend) {
        std::cerr << "error: backend build failed: "
                  << backend.error().detail << '\n';
        return kExitUnexpectedFailure;
    }
    timing.record("cfg discovery", mark);

    mark = SteadyClock::now();
    features::extractors::papa_native::PapaNativeStaticExtractor extractor(
        std::move(*backend));
    timing.record("extractor init", mark);

    mark = SteadyClock::now();
    auto caps = capabilities::static_::find_static_capabilities(
        *ruleset, extractor, /*threads=*/0U, &file_features);
    if (!caps) {
        std::cerr << "error: capability discovery failed: "
                  << caps.error().detail << '\n';
        return kExitUnexpectedFailure;
    }
    timing.record("extract + match", mark);
    if (timing.enabled()) {
        std::cerr << "  workers " << caps->workers
                  << "  per-function " << caps->parallel_seconds
                  << " s  reduce " << caps->reduce_seconds
                  << " s  file-scope " << caps->file_scope_seconds << " s\n";
    }

    mark = SteadyClock::now();
    std::vector<std::string> rules_paths{args.rules_dir.string()};
    auto meta = collect_metadata(
        std::span<const std::byte>(sample_buf),
        args.sample_path,
        args.argv,
        std::move(rules_paths),
        *image,
        *caps,
        extractor);

    // Enrich the metadata with the two pieces only the full pipeline can supply:
    // capa's basic-block layout and the FLIRT name of each library function
    meta.analysis.layout = compute_static_layout(*ruleset, extractor, *caps);
    for (auto& lib : meta.analysis.library_functions) {
        if (const auto* abs =
                std::get_if<features::AbsoluteVirtualAddress>(&lib.address)) {
            lib.name = extractor.flirt_name_at(abs->v).value_or("?");
        }
    }
    timing.record("metadata", mark);

    mark = SteadyClock::now();
    auto doc = render::build_document(std::move(meta), *ruleset, caps->all_matches);
    timing.record("build document", mark);

    // Route the report to a file when --output was given, otherwise stdout
    std::ofstream file_out;
    std::ostream* out = &std::cout;
    if (!args.output_path.empty()) {
        file_out.open(args.output_path, std::ios::binary);
        if (!file_out) {
            std::cerr << "error: cannot open output path: "
                      << args.output_path << '\n';
            return kExitUnexpectedFailure;
        }
        out = &file_out;
    }

    mark = SteadyClock::now();
    switch (args.output) {
        case OutputMode::kJson:
            // capa emits compact JSON (model_dump_json) then a trailing newline
            render::json::render(doc, *out, /*pretty=*/false);
            (*out) << '\n';
            break;
        case OutputMode::kVerbose:
            render::text::render(doc, *out, render::text::Verbosity::kVerbose, color);
            break;
        case OutputMode::kVverbose:
            render::text::render(doc, *out, render::text::Verbosity::kVverbose, color);
            break;
        case OutputMode::kDefault:
            render::text::render(doc, *out, render::text::Verbosity::kDefault, color);
            break;
    }
    out->flush();
    timing.record("render", mark);

    timing.report(std::cerr);
    return kExitOk;
}

}  // namespace papa::cli
