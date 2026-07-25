#include "papa/loader.h"

#include "papa/capabilities/static_.h"
#include "papa/constants.h"
#include "papa/engine.h"
#include "papa/features/address.h"
#include "papa/features/extractors/base_extractor.h"
#include "papa/pe/pe_image.h"
#include "papa/rules/rule.h"
#include "papa/rules/ruleset.h"
#include "papa/rules/scope.h"
#include "papa/util/hash.h"
#include "papa/version.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace papa {

namespace {

// Render the current UTC instant as ISO-8601 (e.g. "2026-05-02T14:23:45Z")
// Uses the C library to keep portability across MSVC, libstdc++, and libc++
[[nodiscard]] std::string utc_iso8601_now() {
    const auto now = std::chrono::system_clock::now();
    const auto t   = std::chrono::system_clock::to_time_t(now);
    std::tm gm{};
#if defined(_WIN32)
    // gmtime_s on MSVC takes the buffer first
    if (gmtime_s(&gm, &t) != 0) { return {}; }
#else
    if (gmtime_r(&t, &gm) == nullptr) { return {}; }
#endif
    std::ostringstream oss;
    // tm_year is years since 1900, tm_mon is 0-based
    oss.fill('0');
    oss.width(4); oss << (gm.tm_year + 1900); oss << '-';
    oss.width(2); oss << (gm.tm_mon + 1);     oss << '-';
    oss.width(2); oss << gm.tm_mday;          oss << 'T';
    oss.width(2); oss << gm.tm_hour;          oss << ':';
    oss.width(2); oss << gm.tm_min;           oss << ':';
    oss.width(2); oss << gm.tm_sec;           oss << 'Z';
    return oss.str();
}

[[nodiscard]] std::string arch_for_machine(std::uint16_t machine) noexcept {
    using namespace ::papa::constants;
    if (machine == kImageFileMachineI386)  { return std::string(arch_value::kI386);  }
    if (machine == kImageFileMachineAmd64) { return std::string(arch_value::kAmd64); }
    if (machine == kImageFileMachineArm64) { return std::string(arch_value::kAarch64); }
    return std::string("unknown");
}

}  // namespace

SampleHashes compute_sample_hashes(std::span<const std::byte> data) {
    SampleHashes out;

    // Three independent passes. Hashing cost is dominated by IO and parsing,
    // so a single combined pass would not be measurably faster
    out.md5    = util::hex_digest(util::md5(data));
    out.sha1   = util::hex_digest(util::sha1(data));
    out.sha256 = util::hex_digest(util::sha256(data));
    return out;
}

Metadata
collect_metadata(std::span<const std::byte>                                 sample_buf,
                 std::filesystem::path                                      sample_path,
                 std::vector<std::string>                                   argv,
                 std::vector<std::string>                                   rules_paths,
                 const pe::PeImage&                                         image,
                 const capabilities::static_::StaticCapabilities&           caps,
                 const features::extractors::StaticFeatureExtractor&        extractor) {
    Metadata m;
    m.timestamp         = utc_iso8601_now();
    m.version           = std::string(version::kVersionString);
    m.argv              = std::move(argv);
    m.sample_path       = std::move(sample_path);
    m.sample_size_bytes = static_cast<std::uint64_t>(sample_buf.size());
    m.hashes            = compute_sample_hashes(sample_buf);

    m.analysis.arch         = arch_for_machine(image.machine());
    m.analysis.os           = std::string(constants::os_value::kWindows);
    m.analysis.format       = std::string(constants::format_value::kPe);
    m.analysis.extractor    = "papa_native";
    m.analysis.rules_paths  = std::move(rules_paths);
    m.analysis.base_address = image.image_base();

    // Library-function names come from FLIRT, which only the concrete extractor
    // exposes, so callers fill them in afterward. Default to capa's "?" sentinel
    m.analysis.library_functions.reserve(caps.library_functions.size());
    for (const auto& addr : caps.library_functions) {
        m.analysis.library_functions.push_back(LibraryFunction{addr, "?"});
    }

    m.analysis.feature_count_file        = caps.feature_count;
    m.analysis.feature_counts_functions  = caps.per_function_feature_counts;
    (void)extractor;
    return m;
}

std::vector<FunctionMatchLayout>
compute_static_layout(const rules::RuleSet&                                 rules,
                      const features::extractors::StaticFeatureExtractor&   extractor,
                      const capabilities::static_::StaticCapabilities&      caps) {
    // Collect the basic blocks where a basic-block-scope rule matched. capa keys
    // these by the match address, which for that scope is the basic block
    std::unordered_set<std::uint64_t> matched_bbs;
    for (const auto& [rule_name, addr_results] : caps.all_matches) {
        const rules::Rule* rule = rules.find(rule_name);
        if (rule == nullptr) { continue; }
        if (rule->meta().scopes.static_scope != rules::Scope::kBasicBlock) { continue; }
        for (const auto& [addr, _result] : addr_results) {
            matched_bbs.insert(features::linearize(addr));
        }
    }

    std::vector<FunctionMatchLayout> layout;
    for (const auto& fh : extractor.get_functions()) {
        std::vector<features::Address> matched;
        for (const auto& bbh : extractor.get_basic_blocks(fh)) {
            if (matched_bbs.count(features::linearize(bbh.addr)) != 0) {
                matched.push_back(bbh.addr);
            }
        }
        if (!matched.empty()) {
            layout.push_back(FunctionMatchLayout{fh.addr, std::move(matched)});
        }
    }
    return layout;
}

}  // namespace papa
