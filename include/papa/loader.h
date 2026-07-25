#pragma once

#include "papa/capabilities/static_.h"
#include "papa/features/address.h"
#include "papa/features/extractors/base_extractor.h"
#include "papa/pe/pe_image.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace papa::rules {
class RuleSet;
}  // namespace papa::rules

namespace papa {

// Three legacy digests of the sample, all lowercase hex
struct SampleHashes {
    std::string md5;
    std::string sha1;
    std::string sha256;
};

// A statically-linked function identified by signature, with its FLIRT name
struct LibraryFunction {
    features::Address address;
    std::string       name;
};

// One function and the basic blocks within it at which some rule matched
// Mirrors capa's FunctionLayout, used to link basic blocks to functions
struct FunctionMatchLayout {
    features::Address              address;
    std::vector<features::Address> matched_basic_blocks;
};

// Static-pipeline metadata that flows directly into the report
struct StaticAnalysisMeta {
    std::string                       arch;          // "i386" or "amd64"
    std::string                       os;            // "windows" for PE
    std::string                       format;        // "pe"
    std::string                       extractor;     // "papa_native"
    std::vector<std::string>          rules_paths;
    std::uint64_t                     base_address{0};
    std::vector<FunctionMatchLayout>  layout;
    std::size_t                                          feature_count_file{0};
    std::vector<capabilities::static_::FunctionFeatureCount> feature_counts_functions;
    std::vector<LibraryFunction>                        library_functions;
};

// Top-level report header
// argv preserves the command-line arguments so users can reproduce a run from
// the report alone (CAPA does the same)
struct Metadata {
    std::string               timestamp;     // ISO-8601 UTC
    std::string               version;       // papa::version::kVersionString
    std::vector<std::string>  argv;
    std::filesystem::path     sample_path;
    std::uint64_t             sample_size_bytes{0};
    SampleHashes              hashes;
    StaticAnalysisMeta        analysis;
};

// Compute md5/sha1/sha256 of the sample buffer in one streaming pass each
// The three digests are independent so we recompute rather than try to share
// state across algorithms (this keeps the helper trivially correct)
[[nodiscard]] SampleHashes compute_sample_hashes(std::span<const std::byte> data);

// Build a Metadata from the analysis output and a few caller-supplied values
// argv and rules_paths are moved in to avoid copying the caller's lists
[[nodiscard]] Metadata
collect_metadata(std::span<const std::byte>                                 sample_buf,
                 std::filesystem::path                                      sample_path,
                 std::vector<std::string>                                   argv,
                 std::vector<std::string>                                   rules_paths,
                 const pe::PeImage&                                         image,
                 const capabilities::static_::StaticCapabilities&           caps,
                 const features::extractors::StaticFeatureExtractor&        extractor);

// Link each matched basic block to its function, mirroring capa's
// compute_static_layout. Only basic blocks where a basic-block-scope rule
// matched are recorded, and only functions that contain at least one are kept
[[nodiscard]] std::vector<FunctionMatchLayout>
compute_static_layout(const rules::RuleSet&                                 rules,
                      const features::extractors::StaticFeatureExtractor&   extractor,
                      const capabilities::static_::StaticCapabilities&      caps);

}  // namespace papa
