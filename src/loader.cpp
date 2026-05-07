#include "papa/loader.h"

#include "papa/capabilities/static_.h"
#include "papa/constants.h"
#include "papa/features/address.h"
#include "papa/features/extractors/base_extractor.h"
#include "papa/pe/pe_image.h"
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
    // Three independent passes
    // The buffers are typically tens of MB so cost is dominated by IO/parsing,
    // not the hash computation
    // Three independent passes keep the code simple at no measurable cost
    out.md5    = util::hex_digest(util::md5(data));
    out.sha1   = util::hex_digest(util::sha1(data));
    out.sha256 = util::hex_digest(util::sha256(data));
    return out;
}

Metadata
collect_metadata(std::span<const std::byte>                                 sample_buf,
                 std::filesystem::path                                      sample_path,
                 std::string                                                argv_string,
                 std::vector<std::string>                                   rules_paths,
                 const pe::PeImage&                                         image,
                 const capabilities::static_::StaticCapabilities&           caps,
                 const features::extractors::StaticFeatureExtractor&        extractor) {
    Metadata m;
    m.timestamp         = utc_iso8601_now();
    m.version           = std::string(version::kVersionString);
    m.argv              = std::move(argv_string);
    m.sample_path       = std::move(sample_path);
    m.sample_size_bytes = static_cast<std::uint64_t>(sample_buf.size());
    m.hashes            = compute_sample_hashes(sample_buf);

    m.analysis.arch        = arch_for_machine(image.machine());
    m.analysis.os          = std::string(constants::os_value::kWindows);
    m.analysis.format      = std::string(constants::format_value::kPe);
    m.analysis.extractor   = "papa_native";
    m.analysis.rules_paths = std::move(rules_paths);

    m.analysis.feature_count_file        = caps.feature_count;
    m.analysis.library_functions         = caps.library_functions;
    m.analysis.feature_counts_functions  = caps.per_function_feature_counts;
    (void)extractor;
    return m;
}

}  // namespace papa
