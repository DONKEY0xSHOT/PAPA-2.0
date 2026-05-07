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

namespace papa {

// Three legacy digests of the sample, all lowercase hex
struct SampleHashes {
    std::string md5;
    std::string sha1;
    std::string sha256;
};

// Static-pipeline metadata that flows directly into the report
struct StaticAnalysisMeta {
    std::string                       arch;        // "i386" or "amd64"
    std::string                       os;          // "windows" for PE
    std::string                       format;      // "pe"
    std::string                       extractor;   // "papa_native"
    std::vector<std::string>          rules_paths;
    std::size_t                       feature_count_file{0};
    std::vector<std::size_t>          feature_counts_functions;
    std::vector<features::Address>    library_functions;
};

// Top-level report header
// argv preserves the literal command line so users can reproduce a run from
// the report alone (CAPA does the same)
struct Metadata {
    std::string             timestamp;       // ISO-8601 UTC
    std::string             version;         // papa::version::kVersionString
    std::string             argv;
    std::filesystem::path   sample_path;
    std::uint64_t           sample_size_bytes{0};
    SampleHashes            hashes;
    StaticAnalysisMeta      analysis;
};

// Compute md5/sha1/sha256 of the sample buffer in one streaming pass each
// The three digests are independent so we recompute rather than try to share
// state across algorithms (this keeps the helper trivially correct)
[[nodiscard]] SampleHashes compute_sample_hashes(std::span<const std::byte> data);

// Build a Metadata from the analysis output and a few caller-supplied strings
// argv is taken by value because callers usually build it on the spot
// rules_paths is moved in to avoid copying the path list
[[nodiscard]] Metadata
collect_metadata(std::span<const std::byte>                                 sample_buf,
                 std::filesystem::path                                      sample_path,
                 std::string                                                argv_string,
                 std::vector<std::string>                                   rules_paths,
                 const pe::PeImage&                                         image,
                 const capabilities::static_::StaticCapabilities&           caps,
                 const features::extractors::StaticFeatureExtractor&        extractor);

}  // namespace papa
